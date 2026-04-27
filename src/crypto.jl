# ==============================================================================
# Stegasaurus
# crypto.jl
# 
# Author: Travis J. Galoppo (tgaloppo@gmail.com)
# Description: Miscellaneous crypto related helper functions.
# 
# SPDX-License-Identifier: MIT
# ==============================================================================

# pads a message to a specific size for AES
function add_pkcs5_padding(data::Vector{UInt8}, block_size::Int=8)
    padding_len = block_size - (length(data) % block_size)
    padding = fill(UInt8(padding_len), padding_len)
    return [data; padding]
end

# removes padding from message
function remove_pkcs5_padding(padded_data::Vector{UInt8}, block_size::Int=8)
    padding_len = Int(padded_data[end])
    # Basic validation: check last byte is not 0 and less than block size
    if padding_len == 0 || padding_len > block_size
        error("Invalid padding")
    end
    return padded_data[1:end-padding_len]
end

# generates a random permutation of 1..size using a PRNG seeded by key/iv
function generate_shuffle(size::Int, key::Vector{UInt8}, iv::Vector{UInt8})::Vector{UInt}
    shuf = Vector{UInt}(undef, size)
    
    # initialize AES block cipher
    enc = Encryptor("AES256", key)
    
    # AES uses 16-byte blocks
    in_block = zeros(UInt8, 16)
    
    # use the first 8 bytes of the IV as the nonce.
    copyto!(in_block, 1, iv, 1, min(8, length(iv)))
    
    # cast the buffer to an array of two 64-bit integers.
    # block_ints[1] is the nonce, block_ints[2] is counter.
    block_ints = reinterpret(UInt64, in_block)
    block_ints[2] = 0 
    
    idx = 1
    while idx <= size
        # encrypt the 16-byte block 
        out_block = encrypt(enc, in_block)
        
        # cast to 64-bit integers
        out_ints = reinterpret(UInt64, out_block)
        
        # process the first 64-bit random integer:
        range1 = UInt64(size - idx + 1)
        shuf[idx] = idx + Int(out_ints[1] % range1)
        idx += 1
        
        if idx > size
            break
        end
        
        # process the second 64-bit random integer:
        range2 = UInt64(size - idx + 1)
        shuf[idx] = idx + Int(out_ints[2] % range2)
        idx += 1
        
        # increment counter for the next block
        block_ints[2] += 1
    end
    
    return shuf
end
