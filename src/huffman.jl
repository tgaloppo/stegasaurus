# ==============================================================================
# Stegasaurus
# huffman.jl
# 
# Author: Travis J. Galoppo (tgaloppo@gmail.com)
# Description: Implements Huffman tree and table building, and message
# encoding and decoding.
# 
# SPDX-License-Identifier: MIT
# ==============================================================================

# basic node for a huffman tree
# "position" is used to generate a random tree
# (effectively a Ceasar cipher)
mutable struct HuffmanNode
    symbol::Int      # 0..256 (256 is EOF), or -1 if not a terminal
    count::UInt64    # cumulative node count
    position::UInt64 # randomized position
    left::Union{HuffmanNode, Nothing}
    right::Union{HuffmanNode, Nothing}
end

# for sorting Huffman nodes; note use of position
Base.isless(a::HuffmanNode, b::HuffmanNode) = a.count == b.count ? a.position < b.position : a.count < b.count

# builds a randomized huffman tree (seeded on crypto key/iv)
# note the use of huffman here is not aimed at compression; the
# goal is to provide a stream with a recognizable end marker (symbol 256);
# the tree is randomized so that the marker is not static.
function build_huffman_tree(key::Vector{UInt8}, iv::Vector{UInt8})
    shuf = generate_shuffle(257, key, iv)
    heap = MutableBinaryMinHeap{HuffmanNode}()
    for j = 0:256
        push!(heap, HuffmanNode(j, 1, shuf[j+1], nothing, nothing))
    end

    while length(heap) > 1
        left = pop!(heap)
        right = pop!(heap)
        push!(heap, HuffmanNode(-1, left.count + right.count, left.position, left, right))
    end

    return pop!(heap)
end

# turn tree into symbol table
function build_huffman_table(node::HuffmanNode, prefix::BitVector=BitVector(), table::Dict{Int, BitVector}=Dict{Int, BitVector}())
    if node.symbol != -1
        table[node.symbol] = prefix
    else
        build_huffman_table(node.left, push!(copy(prefix),  false), table)
        build_huffman_table(node.right, push!(copy(prefix), true), table)
    end
    return table
end

# encode a message based on symbol table
function huff_encode_message(msg::Vector{UInt8}, table::Dict{Int, BitVector})
    result = BitVector()
    for j in eachindex(msg)
        append!(result, table[Int(msg[j])])
    end
    append!(result, table[256])
    return result
end

# decode a message based on huffman tree
function huff_decode_message(msg::BitVector, root::HuffmanNode)
    decoded_bytes = UInt8[]
    curr_node = root

    for bit in msg
        curr_node = bit ? curr_node.right : curr_node.left

        if curr_node.symbol != -1
            if curr_node.symbol == 256
                sz = length(decoded_bytes)
                return decoded_bytes
            else
                push!(decoded_bytes, UInt8(curr_node.symbol))
                curr_node = root
            end
        end
    end

    return nothing
end
