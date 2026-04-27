# ==============================================================================
# Stegasaurus
# stc.jl
# 
# Author: Travis J. Galoppo (tgaloppo@gmail.com)
# Description: Implements Syndrome-Trellis Code embedding / extraction
# 
# SPDX-License-Identifier: MIT
# ==============================================================================

using Random

# we use a 10x2 matrix for syndrome-trellis coding
const STC_NUM_STATES = 1024 # 2^10

# optimal convolutional generator polynomials for
# derived by the Binghamton Digital Data Embedding (DDE) lab
# https://dde.binghamton.edu/download/syndrome/
const STC_POLYS_R2 = UInt16[73, 107]
const STC_POLYS_R3 = UInt16[13, 71, 109]
const STC_POLYS_R4 = UInt16[15, 33, 73, 113]
const STC_POLYS_R5 = UInt16[15, 31, 57, 107, 115]

# decide which one we want to use... this is not
# dynamically selected, for now
const STC_POLY = STC_POLYS_R3

# embeds a payload into an image vector using a least-cost encoding
function stc_embed!(pixels::Vector{UInt8}, costs::Vector{Float64}, message_bits::BitVector)
    num_msg_bits = length(message_bits)
    num_pixels_needed = num_msg_bits * length(STC_POLY)
    
    if num_pixels_needed > length(pixels)
        error("Payload size exceeds image capacity")
    end

    path_costs = fill(Inf, STC_NUM_STATES)
    path_costs[1] = 0.0 # Initialize starting state
    next_costs = Vector{Float64}(undef, STC_NUM_STATES)
    
    # traceback matrix, [states, pixel_index]
    traceback = Matrix{UInt16}(undef, STC_NUM_STATES, num_pixels_needed)
    
    pixel_idx = 1
    
    # forward pass
    for target_boolean in message_bits
        target_bit = target_boolean ? 0x01 : 0x00
        
        # process 3 pixels mapping to this message bit
        for col_idx in eachindex(STC_POLY)
            h_col = STC_POLY[col_idx]
            current_cost = costs[pixel_idx]
            original_lsb = pixels[pixel_idx] & 0x01
            
            fill!(next_costs, Inf)
            
            for s in 0:(STC_NUM_STATES - 1)
                if path_costs[s + 1] == Inf
                    continue
                end
                
                # option 1: output 0
                s0 = s
                c0 = path_costs[s + 1] + (original_lsb == 0x00 ? 0.0 : current_cost)
                if c0 < next_costs[s0 + 1]
                    next_costs[s0 + 1] = c0
                    traceback[s0 + 1, pixel_idx] = s # Record parent state
                end
                
                # option 2: output 1
                s1 = s ⊻ h_col
                c1 = path_costs[s + 1] + (original_lsb == 0x01 ? 0.0 : current_cost)
                if c1 < next_costs[s1 + 1]
                    next_costs[s1 + 1] = c1
                    traceback[s1 + 1, pixel_idx] = s # Record parent state
                end
            end
            
            # update costs
            path_costs .= next_costs
            pixel_idx += 1
        end
        
        # prune invalid paths
        fill!(next_costs, Inf)
        for s in 0:(STC_NUM_STATES - 1)
            if path_costs[s + 1] == Inf
                continue
            end

            # lsb of state is output bit; if it does not match the 
            # target bit, the path is invalid
            if (s & 0x01) == target_bit
                shifted_state = s >> 1 # boundary shift
                next_costs[shifted_state + 1] = path_costs[s + 1]
            end
        end
        path_costs .= next_costs
    end
    
    # now the backward pass...
    
    # find the least final state
    s_curr = argmin(path_costs) - 1
    
    # reset pixel pointer to end
    pixel_idx = num_pixels_needed
    
    # count the number of flips, for statistics output
    flips::UInt64 = 0

    # we need a random number generator for lsb matching
    rng = RandomDevice()

    # walk backward through the message bits
    for msg_idx in num_msg_bits:-1:1
        m_bit = message_bits[msg_idx] ? 0x01 : 0x00
        
        s_curr = (s_curr << 1) | m_bit
        for k in eachindex(STC_POLY)
            s_pix   = traceback[s_curr + 1, pixel_idx]
            out_lsb = (s_pix == s_curr) ? 0x00 : 0x01

            if out_lsb != (pixels[pixel_idx] & 0x01)
                val = Int(pixels[pixel_idx])
                if val == 0
                    val = 1
                elseif val == 255
                    val = 254
                else
                    val = val + (rand(rng, Bool) ? 1 : -1)
                end
                pixels[pixel_idx] = UInt8(val)
                flips += 1
            end

            pixel_idx -= 1
            s_curr = s_pix
        end
    end
    
    return flips
end

# extract a payload from an image vector
function stc_extract(pixels::Vector{UInt8})::BitVector
    num_pixels = length(pixels)
    
    # we extract exactly 1 bit for every column of STC_POLY.
    num_msg_bits = num_pixels ÷ length(STC_POLY)
    extracted_bits = falses(num_msg_bits)
    
    state = UInt16(0)
    pixel_idx = 1
    
    for bit_idx in 1:num_msg_bits  
        # process pixels mapping to this message bit
        for col_idx in eachindex(STC_POLY)
            lsb = pixels[pixel_idx] & 0x01
            
            # If the pixel LSB is 1, XOR the corresponding polynomial into our state
            if lsb == 0x01
                state = state ⊻ STC_POLY[col_idx]
            end
            
            pixel_idx += 1
        end
        
        # lsb of the state is the output bit
        extracted_bits[bit_idx] = (state & 0x01) == 0x01
        
        # shift the register down for the next bit
        state = state >> 1
    end
    
    return extracted_bits
end
