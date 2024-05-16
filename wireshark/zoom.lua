
zoom_o = Proto("zoom_o", "Zoom SFU Encapsulation")
zoom_o.fields.type = ProtoField.new("Type", "zoom_o.type", ftypes.UINT8)
zoom_o.fields.seq = ProtoField.new("Sequence number", "zoom_o.seq", ftypes.UINT16)
zoom_o.fields.dir = ProtoField.new("Direction", "zoom_o.dir", ftypes.UINT8)

zoom_o.fields.unknown = ProtoField.new("Unknown", "zoom_o.unknown", ftypes.BYTES)
zoom_o.fields.tid = ProtoField.new("Transaction ID", "zoom_o.tid", ftypes.BYTES) -- similar to Transaction ID in STUN/TURN
zoom_o.fields.cookie = ProtoField.new("Cookie", "zoom_o.cookie", ftypes.BYTES) -- similar to Magic Cookie in STUN/TURN
zoom_o.fields.ts = ProtoField.new("Timestamp", "zoom_o.ts", ftypes.UINT32)
zoom_o.fields.count = ProtoField.new("Count", "zoom_o.count", ftypes.UINT32)
zoom_o.fields.is_continue = ProtoField.new("Continue?", "zoom_o.is_continue", ftypes.UINT8)
zoom_o.fields.padding = ProtoField.new("Padding", "zoom_o.padding", ftypes.BYTES)
zoom_o.fields.cookie = ProtoField.new("Cookie", "zoom_o.cookie", ftypes.BYTES)

zoom_o.fields.attr_len = ProtoField.new("Attr Length", "zoom_o.attr_len", ftypes.UINT8)
zoom_o.fields.attr_type = ProtoField.new("Attr Type", "zoom_o.attr_type", ftypes.UINT8)

zoom = Proto("zoom", "Zoom Media Encapsulation")
zoom.fields.type = ProtoField.new("Type", "zoom.type", ftypes.UINT8)
zoom.fields.seq = ProtoField.new("Sequence number", "zoom.seq", ftypes.UINT16)
zoom.fields.ts = ProtoField.new("Timestamp", "zoom.ts", ftypes.UINT32)
zoom.fields.frame_num = ProtoField.new("Frame number", "zoom.frame_num", ftypes.UINT16)
zoom.fields.frame_pkt_count = ProtoField.new("Packets in frame", "zoom.frame_pkt_count", ftypes.UINT8)
zoom.fields.unknown = ProtoField.new("Unknown", "zoom.unknown", ftypes.BYTES)

zoom.fields.t13ts = ProtoField.new("T13 Timestamp", "zoom.t13ts", ftypes.UINT16)
zoom.fields.t13s = ProtoField.new("T13 Sequence number", "zoom.t13s", ftypes.UINT16)
zoom.fields.t13t = ProtoField.new("T13 Subtype", "zoom.t13t", ftypes.UINT8)
zoom.fields.t32ts = ProtoField.new("T32 Timestamp", "zoom.t32ts", ftypes.UINT32)

function get_type_desc(type)
    local desc = "Unknown"

    if type == 13 then
        desc = "Screen Share"
    elseif type == 15 then
        desc = "Audio"
    elseif type == 16 then
        desc = "Video"
    elseif type == 30 then
        desc = "Screen Share"
    elseif type == 33 or type == 34 or type == 35 then
        desc = "RTCP"
    end

    return desc
end

function get_zoom_o_dir_desc(dir)
    local desc = "Unknown"

    if dir == 0 then
        desc = "to Zoom"
    elseif dir == 4 then
        desc = "from Zoom"
    end

    return desc
end

-- Zoom media encapsulation (inner header):
function zoom.dissector(buf, pkt, tree)
    len = buf:len()
    if len == 0 then return end
    pkt.cols.protocol = zoom.name --name is defined in the Proto() call above. For example, zoom_o.name is "Zoom SFU Encapsulation"

    local inner_type = buf(0, 1):uint() -- 0 is the offset, 1 is the length

    local t = tree:add(zoom, buf(), "Zoom Media Encapsulation")
    t:add(zoom.fields.type, buf(0, 1)):append_text(" (" .. get_type_desc(inner_type) .. ")")

    if inner_type == 1 then
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))
        Dissector.get("rtp"):call(buf(26):tvb(), pkt, tree) -- tvb() is the buffer containing the data
    elseif inner_type == 13 then
        t:add(zoom.fields.t13ts, buf(1, 2))
        t:add(zoom.fields.t13s, buf(3, 2))
        t:add(zoom.fields.t13t, buf(7, 1))

        if buf(7, 1):uint() == 0x1e then -- server screen sharing
            t:add(zoom.fields.seq, buf(16, 2))
            t:add(zoom.fields.ts, buf(18, 4))
            Dissector.get("rtp"):call(buf(27):tvb(), pkt, tree)
        end

    elseif inner_type == 15 then
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))
        t:add(zoom.fields.unknown, buf(15, 4))
        Dissector.get("rtp"):call(buf(19):tvb(), pkt, tree)
    elseif inner_type == 16 then
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))
        t:add(zoom.fields.unknown, buf(15, 6))
        if (buf(20, 1):uint() == 0x02) then
            t:add(zoom.fields.frame_num, buf(21, 2))
            t:add(zoom.fields.frame_pkt_count, buf(23, 1))
            Dissector.get("rtp"):call(buf(24):tvb(), pkt, tree)
        else
            Dissector.get("rtp"):call(buf(20):tvb(), pkt, tree)
        end

    elseif inner_type == 21 then -- unclear what this type is
        t:add(zoom.fields.seq, buf(13, 2))
    elseif inner_type == 30 then -- P2P screen sharing
        t:add(zoom.fields.seq, buf(9, 2))
        t:add(zoom.fields.ts, buf(11, 4))
        Dissector.get("rtp"):call(buf(20):tvb(), pkt, tree)
    elseif inner_type == 32 then -- unclear what this type is
        t:add(zoom.fields.t32ts, buf(19, 4))
    elseif inner_type == 33 or inner_type == 34 or inner_type == 35 then
        Dissector.get("rtcp"):call(buf(16):tvb(), pkt, tree)
    else
        Dissector.get("data"):call(buf(15):tvb(), pkt, tree)
    end
end

-- Zoom server encapsulation (outer header):
function zoom_o.dissector(buf, pkt, tree)
    length = buf:len()
    if length == 0 then return end
    pkt.cols.protocol = zoom_o.name

    local t = tree:add(zoom_o, buf(), "Zoom SFU Encapsulation")
    local outer_type = buf(0, 1):uint()
    t:add(zoom_o.fields.type, buf(0, 1))
    if outer_type == 5 then
        t:add(zoom_o.fields.seq, buf(1, 2))
        t:add(zoom_o.fields.cookie, buf(3, 4))
        t:add(zoom_o.fields.dir, buf(7, 1)):append_text(" (" .. get_zoom_o_dir_desc(buf(7, 1):uint()) .. ")")
        Dissector.get("zoom"):call(buf(8):tvb(), pkt, tree)
    elseif outer_type == 3 or outer_type == 4 then
        -- t:add(zoom_o.fields.unknown, buf(1, 12))
        t:add(zoom_o.fields.count, buf(1, 4))
        t:add(zoom_o.fields.ts, buf(5, 4))
        t:add(zoom_o.fields.cookie, buf(9, 4))
        t:add(zoom_o.fields.is_continue, buf(13, 1))
        local is_continue = buf(13, 1):uint() -- 0x01 if there is more data
        if is_continue == 0x01 then
            local attr = t:add(zoom_o, buf(), "Attributes")
            buf = buf(14)
            while buf:len() > 2 do
                local len = buf(1, 1):uint()
                local attr_type = buf(0, 1):uint()
                local attr_buf = buf(2, len)
                local attr_tree = attr:add(attr_buf, "Attribute")
                attr_tree:add(zoom_o.fields.attr_type, buf(0, 1))
                attr_tree:add(zoom_o.fields.attr_len, buf(1, 1))
                attr_tree:add(zoom_o.fields.unknown, attr_buf)
                -- buf = buf(2 + len)
                local rest_len = buf(2 + len - 1):len()
                if rest_len > 5 then
                    buf = buf(2 + len)
                else
                    buf = buf(2 + len - 1)
                    break
                end
            end
        else
            buf = buf(13)
        end
        local padding_len = buf:len()
        if padding_len > 1 then
            t:add(zoom_o.fields.padding, buf(1,padding_len-1))
        end
    elseif outer_type == 1 then
        t:add(zoom_o.fields.unknown, buf(1, 2))
        t:add(zoom_o.fields.tid, buf(3, 16))
        t:add(zoom_o.fields.unknown, buf(19, 4))
        t:add(zoom_o.fields.unknown, buf(23, 4))
        t:add(zoom_o.fields.ts, buf(27, 4))
        t:add(zoom_o.fields.ts, buf(31, 4))
        t:add(zoom_o.fields.attr_len, buf(35, 4))
        local len = buf(35, 4):uint()
        t:add(zoom_o.fields.unknown, buf(39, len))
        buf = buf(39 + len)
        t:add(zoom_o.fields.unknown, buf(0, 4))
        t:add(zoom_o.fields.unknown, buf(4, 16))
        t:add(zoom_o.fields.attr_len, buf(17, 1))
        local len = buf(17, 1):uint()
        t:add(zoom_o.fields.is_continue, buf(19, 1))
        local is_continue = buf(19, 1):uint() -- 0x01 if there is more data
        if is_continue == 0x01 then
            local attr = t:add(zoom_o, buf(), "Attributes")
            buf = buf(20)
            while buf:len() > 2 do
                local len = buf(1, 1):uint()
                local attr_type = buf(0, 1):uint()
                local attr_buf = buf(2, len)
                local attr_tree = attr:add(attr_buf, "Attribute")
                attr_tree:add(zoom_o.fields.attr_type, buf(0, 1))
                attr_tree:add(zoom_o.fields.attr_len, buf(1, 1))
                attr_tree:add(zoom_o.fields.unknown, attr_buf)
                local rest_len = buf(2 + len - 1):len()
                if rest_len > 5 then
                    buf = buf(2 + len)
                else
                    buf = buf(2 + len - 1)
                    break
                end
            end
        else
            buf = buf(19)
        end
        local padding_len = buf:len()
        if padding_len > 1 then
            t:add(zoom_o.fields.padding, buf(1,padding_len-1))
        end
    elseif outer_type == 2 then
        t:add(zoom_o.fields.unknown, buf(1, 2))
        t:add(zoom_o.fields.tid, buf(3, 16))
        t:add(zoom_o.fields.cookie, buf(19, 4))
        t:add(zoom_o.fields.ts, buf(23, 4))
        t:add(zoom_o.fields.unknown, buf(27, 16))
        t:add(zoom_o.fields.attr_len, buf(40, 1))
        local len = buf(40, 1):uint()
        t:add(zoom_o.fields.is_continue, buf(43, 1))
        local is_continue = buf(43, 1):uint() -- 0x01 if there is more data
        if is_continue == 0x01 then
            local attr = t:add(zoom_o, buf(), "Attributes")
            buf = buf(44)
            while buf:len() > 2 do
                local len = buf(1, 1):uint()
                local attr_type = buf(0, 1):uint()
                local attr_buf = buf(2, len)
                local attr_tree = attr:add(attr_buf, "Attribute")
                attr_tree:add(zoom_o.fields.attr_type, buf(0, 1))
                attr_tree:add(zoom_o.fields.attr_len, buf(1, 1))
                attr_tree:add(zoom_o.fields.unknown, attr_buf)
                local rest_len = buf(2 + len - 1):len()
                if rest_len > 5 then
                    buf = buf(2 + len)
                else
                    buf = buf(2 + len - 1)
                    break
                end
            end
        end
    elseif outer_type == 7 then
        t:add(zoom_o.fields.unknown, buf(1, 4))
        if buf:len() > 5 then
            t:add(zoom_o.fields.cookie, buf(5, 4))
            t:add(zoom_o.fields.is_continue, buf(9, 1))
            local is_continue = buf(9, 1):uint() -- 0x01 if there is more data
            if is_continue == 0x01 then
                local attr = t:add(zoom_o, buf(), "Attributes")
                buf = buf(10)
                while buf:len() > 2 do
                    local len = buf(1, 1):uint()
                    local attr_type = buf(0, 1):uint()
                    local attr_buf = buf(2, len)
                    local attr_tree = attr:add(attr_buf, "Attribute")
                    attr_tree:add(zoom_o.fields.attr_type, buf(0, 1))
                    attr_tree:add(zoom_o.fields.attr_len, buf(1, 1))
                    attr_tree:add(zoom_o.fields.unknown, attr_buf)
                    local rest_len = buf(2 + len - 1):len()
                    if rest_len > 5 then
                        buf = buf(2 + len)
                    else
                        buf = buf(2 + len - 1)
                        break
                    end
                end
            else
                buf = buf(9)
            end
            local padding_len = buf:len()
            if padding_len > 1 then
                t:add(zoom_o.fields.padding, buf(1,padding_len-1))
            end
        end
    else
        Dissector.get("data"):call(buf(1):tvb(), pkt, tree)
    end
end

-- per-default dissect all UDP port 8801 as Zoom Server Encap.
DissectorTable.get("udp.port"):add(8801, zoom_o)

-- allow selecting Zoom from "Decode as ..." context menu (for P2P traffic):
DissectorTable.get("udp.port"):add_for_decode_as(zoom)
