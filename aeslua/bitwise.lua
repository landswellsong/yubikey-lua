-- Lua 5.2 replaced bitlib with bit32 builtin
if _VERSION:match("%d.(%d)") == "2" then
    return bit32
-- Oh, it's Lua 5.1, let's require bitlib then
else
    return require("bit");
end
