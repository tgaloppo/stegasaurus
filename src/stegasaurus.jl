# ==============================================================================
# Stegasaurus
# stegasaurus.jl
# 
# Author: Travis J. Galoppo (tgaloppo@gmail.com)
# Description: This is the main entrypoint for Stegasaurus
# 
# SPDX-License-Identifier: MIT
# ==============================================================================
module stegasaurus

using ArgParse
using Base: getpass
using CRC
using DataStructures
using Images
using ImageIO
using Nettle
using Random
using SHA

include("huffman.jl")
include("crypto.jl")
include("stc.jl")

function parse_commandline()
    s = ArgParseSettings()

    @add_arg_table! s begin
        "embed", "E"
            help = "Embed Mode"
            action = :command
        "extract", "X"
            help = "Extract Mode"
            action = :command
    end

    @add_arg_table! s["embed"] begin
        "--message", "-m"
            help = "Message to embed"
            arg_type = String
        "--file", "-f"
            help = "Data file to embed"
            arg_type = String
        "--stats", "-s"
            help = "Output statistics"
            action = :store_true
        "input_file"
            help = "Input image file"
            arg_type = String
            required = true
        "output_file"
            help = "Output image file"
            arg_type = String
            required = true            
    end

    @add_arg_table! s["extract"] begin
        "input_file"
            help = "Input image file"
            arg_type = String
            required = true
        "output_file"
            help = "Output image file"
            arg_type = String
            default = "-"
    end

    return parse_args(s)
end

# load image file into flat vector
function load_image_raw(path::String)
    img = load(path)
    img_rgb = RGB.(img)
    raw = reinterpret(UInt8, channelview(img_rgb))
    return vec(collect(raw)), size(img_rgb)
end

# save flat vector of pixels as image
function save_image_raw(path::String, data::Vector{UInt8}, dims::Tuple{Int, Int})
    raw_reshaped = reshape(data, (3, dims[1], dims[2]))
    img = colorview(RGB, reinterpret(N0f8, raw_reshaped))
    save(path, img)
end

# shuffle entries of vector according to specified shuffle order
function shuffle_forward!(buffer::AbstractVector, shuffle::Vector{UInt})
    for j in eachindex(buffer)
        k = shuffle[j]
        tmp = buffer[j]
        buffer[j] = buffer[k]
        buffer[k] = tmp
    end
end

# un-shuffle vector entries according to shuffle order
function shuffle_backward!(buffer::AbstractVector, shuffle::Vector{UInt})
    for j=length(buffer):-1:1
        k = shuffle[j]
        tmp = buffer[j]
        buffer[j] = buffer[k]
        buffer[k] = tmp
    end
end

# compute a cost matrix based on the local variance for each 
# pixel in an image, defined as the variance of the 5x5 pixel 
# block centered on the pixel of interest. Cost is the inverse
# of the local variance.
function compute_costs(raw_buffer::Vector{UInt8}, img_dims::Tuple{Int, Int})::Vector{Float64}
    # reshape to (channel, height, width)
    img_3d = reshape(raw_buffer, 3, img_dims[1], img_dims[2]) 
    
    # cost vector
    costs = Vector{Float64}(undef, length(raw_buffer))
    costs_3d = reshape(costs, 3, img_dims[1], img_dims[2])
    
    h, w = img_dims
    eps = 0.01 # prevent division by zero
    
    # process each color channel
    for c in 1:3
        for y in 1:h
            for x in 1:w
                # 5x5 window boundaries, clamped to the image edges
                y_min = max(1, y - 2)
                y_max = min(h, y + 2)
                x_min = max(1, x - 2)
                x_max = min(w, x + 2)
                
                sum_val = 0.0
                sq_sum = 0.0
                count = 0
                
                # iterate over the 5x5 patch
                for wy in y_min:y_max
                    for wx in x_min:x_max
                        val = Float64(img_3d[c, wy, wx])
                        sum_val += val
                        sq_sum += val * val
                        count += 1
                    end
                end
                
                # calculate the local variance for this pixel's patch
                mean = sum_val / count
                variance = max(0.0, (sq_sum / count) - (mean * mean))
                
                # cost = inverse variance 
                costs_3d[c, y, x] = 1.0 / (variance + eps)
            end
        end
    end
    
    return costs
end

# embed a payload into an image
function do_embed(args)
    # extract parameters
    input_path  = args["input_file"]
    output_path = args["output_file"]
    data_path   = args["file"]
        
    # check to make sure input image exists
    if !isfile(input_path)
        println(stderr, "Image '$input_path' not found.")
        return
    end

    # check to make sure a payload was supplied
    if isnothing(args["message"]) && isnothing(args["file"])
        println(stderr, "A message or a data file must be specified")
        return
    end

    # check to make sure only one payload was supplied
    if !isnothing(args["message"]) && !isnothing(args["file"])
        println(stderr, "Only one of -f or -m can be specified")
        return
    end

    # get message bytes, either from command line
    # or from specified file
    msg_bytes = Vector{UInt8}()
    if !isnothing(args["message"])
        msg_bytes = Vector{UInt8}(args["message"])
    else
        if !isfile(data_path)
            println(stderr, "Data file $data_file not found")
            return
        end
        open(data_path, "r") do fd
            msg_bytes = read(fd)
        end
    end
        
    # no message? nothing to do
    if isempty(msg_bytes)
        println(stderr, "Error: No data to embed.")
        return
    end

    # request encryption password with verification
    pwd = getpass("Password"); println()
    ver = getpass("Verify Password"); println()
    if pwd != ver
        println(stderr, "Passwords do not match")
        return
    end
    Base.shred!(ver)
        
    # read the image file
    raw_buffer, img_dims = load_image_raw(input_path)

    # prepare 32 byte key and initialization vector
    # note use of password for salt -- do not reuse passwords!
    salt = sha256(pwd)
    seekstart(pwd)
    key, iv = gen_key32_iv16(Vector{UInt8}(read(pwd)), salt)
    Base.shred!(pwd)

    # compute message CRC
    msg_crc = crc(CRC_64)(msg_bytes)
    crc_bytes = collect(reinterpret(UInt8, [hton(msg_crc)]))

    # encrypt the message and append the crc
    cipher = encrypt("AES256", :CBC, iv, key, add_pkcs5_padding(msg_bytes, 16))
    payload = [cipher; crc_bytes]

    # build a huffman table based on the key/iv, and encode the encrypted message
    huff_tree = build_huffman_tree(key, iv)
    huff_table = build_huffman_table(huff_tree)
    message_bits = huff_encode_message(payload, huff_table)

    # compute the per-pixel costs for lsb flips
    costs = compute_costs(raw_buffer, img_dims)

    # shuffle the image pixels (and costs)
    shuf = generate_shuffle(length(raw_buffer), key, iv)
    shuffle_forward!(raw_buffer, shuf)
    shuffle_forward!(costs, shuf)

    # embed the payload into the image pixels
    flips = stc_embed!(raw_buffer, costs, message_bits)

    # unshuffle the pixels
    shuffle_backward!(raw_buffer, shuf)

    # write out the image
    save_image_raw(output_path, raw_buffer, img_dims)

    # Collect and report post stats, if requested
    if args["stats"]
        msg_size = length(message_bits)
        avail_size = img_dims[1] * img_dims[2] * 3
        usage_pct = round(100.0 * msg_size / avail_size, digits=2)
        flip_pct = round(100.0 * flips / avail_size, digits=2)
        println("Message Size: $msg_size bits, Capacity Used: $usage_pct%, Total Change: $flip_pct%")
    end
end

function do_extract(args)
    # extract parameters
    input_path  = args["input_file"]
    output_path = args["output_file"]
        
    # check if input file exists
    if !isfile(input_path)
        println("Error: Image '$input_path' not found.")
        return
    end

    # get the password
    pwd = getpass("Password")
    println()
    
    # read the image
    img_bytes, _ = load_image_raw(input_path)
       
    # generate key and iv from password
    salt = sha256(pwd)
    seekstart(pwd)
    key, iv = gen_key32_iv16(Vector{UInt8}(read(pwd)), salt)
    Base.shred!(pwd)

    # build the keyed huffman tree
    huff_tree = build_huffman_tree(key, iv)

    # shuffle the pixels
    shuf = generate_shuffle(length(img_bytes), key, iv)
    shuffle_forward!(img_bytes, shuf) 

    # extract the payload from the pixels
    message_bits = stc_extract(img_bytes)

    # decode the pixels using huffman tree
    decoded = huff_decode_message(message_bits, huff_tree)

    # decode will fail if no EOF marker is found
    # (no payload or wrong password)
    if isnothing(decoded) || length(decoded) < 24
        println(stderr, "No message found.")
        return
    end

    try
        # split cipher and CRC
        cipher    = decoded[1:end-8]
        crc_bytes = decoded[end-7:end]
          
        # decrypt the message payload
        recovered = decrypt("AES256", :CBC, iv, key, cipher)
        msg_out = remove_pkcs5_padding(recovered, 16)
            
        # compute and verify CRC
        # if the password was incorrect, or if there is no
        # embedded payload, there is a strong chance the decode
        # will run into a random EOF; the CRC validates a successful
        # decode. Very small probability of a random "successful"
        # decode.
        stored_crc = ntoh(reinterpret(UInt64, crc_bytes)[1])
        msg_crc    = crc(CRC_64)(msg_out)
            
        # if the CRC matches, output the message
        if stored_crc == msg_crc
            if output_path == "-"
                write(stdout, msg_out)
            else
                open(output_path, "w") do fd
                    write(fd, msg_out)
                end
            end
        else
            println(stderr, "No message found.")
        end
    catch e
        println(stderr, "No message found.")
    end
end

function main()
    parsed_args = parse_commandline()

    cmd = parsed_args["%COMMAND%"]
    args = parsed_args[cmd]

    if cmd == "embed"
        do_embed(args)
    else
        do_extract(args)
    end
end

if abspath(PROGRAM_FILE) == @__FILE__
    main()
end

end # end module
