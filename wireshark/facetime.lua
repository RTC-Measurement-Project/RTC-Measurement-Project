facetime = Proto("facetime", "FaceTime Encapsulation")

-- Register fields
facetime.fields.unknown = ProtoField.new("Unknown", "facetime.unknown", ftypes.BYTES)
facetime.fields.qh = ProtoField.new("QUIC Header", "facetime.qh", ftypes.BYTES)
facetime.fields.len = ProtoField.new("Length", "facetime.len", ftypes.UINT32)

facetime.fields.type0 = ProtoField.new("Raw Type", "facetime.type0", ftypes.BYTES)
facetime.fields.type1 = ProtoField.new("Outer Type", "facetime.type1", ftypes.BYTES)
facetime.fields.type2 = ProtoField.new("Inner Type", "facetime.type2", ftypes.BYTES)
facetime.fields.headlen = ProtoField.new("Header Length", "facetime.headlen", ftypes.UINT32)

facetime.fields.token2b = ProtoField.new("2B Token", "facetime.token2b", ftypes.BYTES)
facetime.fields.token8b = ProtoField.new("8B Token", "facetime.token8b", ftypes.BYTES)
facetime.fields.token12b = ProtoField.new("12B Token", "facetime.token12b", ftypes.BYTES)
facetime.fields.mcount = ProtoField.new("Mark Count", "facetime.mcount", ftypes.UINT8)
facetime.fields.mark1 = ProtoField.new("Prev Mark", "facetime.mark1", ftypes.BYTES)
facetime.fields.mark2 = ProtoField.new("Next Mark", "facetime.mark2", ftypes.BYTES)

facetime.fields.flag = ProtoField.new("Mid Flag", "facetime.flag", ftypes.BYTES)

facetime.fields.count1b = ProtoField.new("1B Counter", "facetime.count1b", ftypes.UINT32)
facetime.fields.count2b = ProtoField.new("2B Counter", "facetime.count2b", ftypes.UINT32)
facetime.fields.count3b = ProtoField.new("3B Counter", "facetime.count3b", ftypes.UINT32)

dcid = Field.new("quic.dcid")

-- FaceTime encapsulation dissector function
function facetime.dissector(buf, pkt, tree)
    local len = buf:len()
    if len == 0 then return end
    
    local quic_header = buf(0, 1):uint()
    if quic_header == 0x00 or quic_header == 0x01 then
        Dissector.get("stun-udp"):call(buf, pkt, tree)
        return
    end
    -- check long quic header, if so, call quic dissector
    if bit.band(quic_header, 0x80) == 0x80 and quic_header ~= 0xde then -- avoid 0xdeadbeef
        Dissector.get("quic"):call(buf, pkt, tree)
        return
    end
    Dissector.get("quic"):call(buf, pkt, tree)

    -- Define the main tree for FaceTime encapsulation
    local t = tree:add(facetime, buf(), "FaceTime Encapsulation")
    t:add(facetime.fields.qh, buf(0, 1))

    if quic_header == 0x60 then
        t:add(facetime.fields.type0, buf(1, 1))
        t:add(facetime.fields.len, buf(2, 2))
        local len = buf(2, 2):uint()
        content = buf(4, len)
        buf = buf(4 + len):tvb()
        local len1 = content:len()

        t:add(facetime.fields.type1, content(0, 1))
        t:add(facetime.fields.type2, content(1, 1))
        local flag_rtp = true
        local type1 = content(0, 1):uint()
        local type1A = bit.band(type1, 0xf0)
        local type1B = bit.band(type1, 0x0f)
        local type2 = content(1, 1):uint()
        local type2A = bit.band(type2, 0xf0)
        local type2B = bit.band(type2, 0x0f)
        content = content(2)


        -- Check Head
        local head_tree = t:add(facetime, content, "Head")
        -- if type1A == 0x00 or type1A == 0x20 then
        if type1A == 0x80 or type1A == 0xa0 then
            head_tree:add(facetime.fields.unknown, content(0, 2))
            content = content(2)
        end

        -- Check Body
        local body_tree = t:add(facetime, content, "Body")
        -- if type2B == 0x0 or type2B == 0x8 then
        if type2B == 0x1 or type2B == 0x9 then
            body_tree:add(facetime.fields.token2b, content(0, 2))
            content = content(2)
        elseif type2B == 0x3 or type2B == 0xb then
            body_tree:add(facetime.fields.mcount, content(2, 1))
            body_tree:add(facetime.fields.mark1, content(0, 2))
            local mcount = content(2, 1):uint()
            for i = 0, mcount - 1 do
                if i < math.floor(mcount/2) then
                    body_tree:add(facetime.fields.mark1, content(3 + i * 2, 2))
                else
                    body_tree:add(facetime.fields.mark2, content(3 + i * 2, 2))
                end
            end
            content = content(3 + mcount * 2)
        elseif type2B == 0x4 or type2B == 0xc then
            body_tree:add(facetime.fields.token8b, content(0, 8))
            content = content(8)
        elseif type2B == 0x5 or type2B == 0xd then
            body_tree:add(facetime.fields.unknown, content(0, 2))
            body_tree:add(facetime.fields.token8b, content(2, 8))
            content = content(10)
        elseif type2B == 0x7 or type2B == 0xf then
            body_tree:add(facetime.fields.mcount, content(2, 1))
            body_tree:add(facetime.fields.mark1, content(0, 2))
            local mcount = content(2, 1):uint()
            for i = 0, mcount - 1 do
                if i < math.floor(mcount/2) then
                    body_tree:add(facetime.fields.mark1, content(3 + i * 2, 2))
                else
                    body_tree:add(facetime.fields.mark2, content(3 + i * 2, 2))
                end
            end
            content = content(3 + mcount * 2)
            body_tree:add(facetime.fields.token8b, content(0, 8))
            content = content(8)
        end

        -- Check Mid
        local mid_tree = t:add(facetime, content, "Mid")
        -- if type1B == 0x0 then
        if type2B >= 0x8 and type2B <= 0xf then
            mid_tree:add(facetime.fields.flag, content(0, 1))
            content = content(1)
        end

        -- Check Counter
        local counter_tree = t:add(facetime, content, "Counter")
        if type2A == 0x00 or type2A == 0x40 then
            if type1B == 0x2 or type1B == 0x3 then
                counter_tree:add(facetime.fields.count2b, content(0, 2))
                if content:len() > 2 then
                    content = content(2)
                else
                    flag_rtp = false
                end
            end
        elseif type2A == 0x20 or type2A == 0x60 then
            counter_tree:add(facetime.fields.count1b, content(0, 1))
            content = content(1)
        elseif type2A == 0x50 then
            counter_tree:add(facetime.fields.count2b, content(0, 2))
            content = content(2)
        elseif type2A == 0x70 then
            counter_tree:add(facetime.fields.count3b, content(0, 3))
            content = content(3)
        end

        -- Check Tail
        local tail_tree = t:add(facetime, content, "Tail")
        if type1A == 0x20 or type1A == 0xa0 then
            tail_tree:add(facetime.fields.unknown, content(0, 2))
            content = content(2)
        elseif type1B == 0x6 or type1B == 0x7 then
            tail_tree:add(facetime.fields.token12b, content(0, 12))
            if content:len() > 12 then
                content = content(12)
            else
                flag_rtp = false
            end
        end
        
        if flag_rtp then
            local len2 = content:len()
            local delta_len = len1 - len2 + 3
            t:add(facetime.fields.headlen, delta_len)
            local four_bytes = content(0, 2):uint()
            if four_bytes ~= 0xface then -- avoid 0xface
                Dissector.get("rtp"):call(content:tvb(), pkt, tree)
            else
                Dissector.get("data"):call(content:tvb(), pkt, tree)
            end
        end
    else
        local dcid_len = 0
        if dcid() then
            print(tostring(dcid()))
            dcid_len = dcid().len
            t:add(facetime.fields.unknown, buf(1, dcid_len))
        end
        buf = buf(dcid_len+1):tvb()
    end
    Dissector.get("data"):call(buf, pkt, tree)
    -- Set the protocol column to show the protocol name
    -- pkt.cols.protocol = facetime.name
end

-- Register the dissector to UDP port table for "Decode As..." functionality
DissectorTable.get("udp.port"):add(16393, facetime)
DissectorTable.get("udp.port"):add(16394, facetime)
DissectorTable.get("udp.port"):add_for_decode_as(facetime)