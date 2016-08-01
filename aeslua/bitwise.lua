local bitops = {}

-- Lua 5.2 replaced bitlib with bit32 builtin
if _VERSION:match("%d.(%d)") == "2" then
    bitops = bit32
    return bitops
-- Oh, it's Lua 5.1, let's require bitlib then
else
    bitops = require("bit")
    return bitops
end
