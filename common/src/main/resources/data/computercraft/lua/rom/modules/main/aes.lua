-- Advanced Encryption Standard (AES) libary for CC: Tweaked
-- (c) 2024 afonya All rights reserved.
-- MIT License
-- Link: https://gist.github.com/afonya2/489c3306a7d85f8f9512df321d904dbb
-- Documentation: https://gist.github.com/afonya2/489c3306a7d85f8f9512df321d904dbb#file-docs-md
-- Last updated: February 25 2024
local SBox = {[0]=99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22}
local InvSBox = {[0]=82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125}
local mul_2 = {[0]=0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,
32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62,
64,66,68,70,72,74,76,78,80,82,84,86,88,90,92,94,
96,98,100,102,104,106,108,110,112,114,116,118,120,122,124,126,
128,130,132,134,136,138,140,142,144,146,148,150,152,154,156,158,
160,162,164,166,168,170,172,174,176,178,180,182,184,186,188,190,
192,194,196,198,200,202,204,206,208,210,212,214,216,218,220,222,
224,226,228,230,232,234,236,238,240,242,244,246,248,250,252,254,
27,25,31,29,19,17,23,21,11,9,15,13,3,1,7,5,
59,57,63,61,51,49,55,53,43,41,47,45,35,33,39,37,
91,89,95,93,83,81,87,85,75,73,79,77,67,65,71,69,
123,121,127,125,115,113,119,117,107,105,111,109,99,97,103,101,
155,153,159,157,147,145,151,149,139,137,143,141,131,129,135,133,
187,185,191,189,179,177,183,181,171,169,175,173,163,161,167,165,
219,217,223,221,211,209,215,213,203,201,207,205,195,193,199,197,
251,249,255,253,243,241,247,245,235,233,239,237,227,225,231,229}
local mul_3 = {[0]=0,3,6,5,12,15,10,9,24,27,30,29,20,23,18,17,
48,51,54,53,60,63,58,57,40,43,46,45,36,39,34,33,
96,99,102,101,108,111,106,105,120,123,126,125,116,119,114,113,
80,83,86,85,92,95,90,89,72,75,78,77,68,71,66,65,
192,195,198,197,204,207,202,201,216,219,222,221,212,215,210,209,
240,243,246,245,252,255,250,249,232,235,238,237,228,231,226,225,
160,163,166,165,172,175,170,169,184,187,190,189,180,183,178,177,
144,147,150,149,156,159,154,153,136,139,142,141,132,135,130,129,
155,152,157,158,151,148,145,146,131,128,133,134,143,140,137,138,
171,168,173,174,167,164,161,162,179,176,181,182,191,188,185,186,
251,248,253,254,247,244,241,242,227,224,229,230,239,236,233,234,
203,200,205,206,199,196,193,194,211,208,213,214,223,220,217,218,
91,88,93,94,87,84,81,82,67,64,69,70,79,76,73,74,
107,104,109,110,103,100,97,98,115,112,117,118,127,124,121,122,
59,56,61,62,55,52,49,50,35,32,37,38,47,44,41,42,
11,8,13,14,7,4,1,2,19,16,21,22,31,28,25,26}
local mul_9 = {[0]=0,9,18,27,36,45,54,63,72,65,90,83,108,101,126,119,
144,153,130,139,180,189,166,175,216,209,202,195,252,245,238,231,
59,50,41,32,31,22,13,4,115,122,97,104,87,94,69,76,
171,162,185,176,143,134,157,148,227,234,241,248,199,206,213,220,
118,127,100,109,82,91,64,73,62,55,44,37,26,19,8,1,
230,239,244,253,194,203,208,217,174,167,188,181,138,131,152,145,
77,68,95,86,105,96,123,114,5,12,23,30,33,40,51,58,
221,212,207,198,249,240,235,226,149,156,135,142,177,184,163,170,
236,229,254,247,200,193,218,211,164,173,182,191,128,137,146,155,
124,117,110,103,88,81,74,67,52,61,38,47,16,25,2,11,
215,222,197,204,243,250,225,232,159,150,141,132,187,178,169,160,
71,78,85,92,99,106,113,120,15,6,29,20,43,34,57,48,
154,147,136,129,190,183,172,165,210,219,192,201,246,255,228,237,
10,3,24,17,46,39,60,53,66,75,80,89,102,111,116,125,
161,168,179,186,133,140,151,158,233,224,251,242,205,196,223,214,
49,56,35,42,21,28,7,14,121,112,107,98,93,84,79,70}
local mul_11 = {[0]=0,11,22,29,44,39,58,49,88,83,78,69,116,127,98,105,
176,187,166,173,156,151,138,129,232,227,254,245,196,207,210,217,
123,112,109,102,87,92,65,74,35,40,53,62,15,4,25,18,
203,192,221,214,231,236,241,250,147,152,133,142,191,180,169,162,
246,253,224,235,218,209,204,199,174,165,184,179,130,137,148,159,
70,77,80,91,106,97,124,119,30,21,8,3,50,57,36,47,
141,134,155,144,161,170,183,188,213,222,195,200,249,242,239,228,
61,54,43,32,17,26,7,12,101,110,115,120,73,66,95,84,
247,252,225,234,219,208,205,198,175,164,185,178,131,136,149,158,
71,76,81,90,107,96,125,118,31,20,9,2,51,56,37,46,
140,135,154,145,160,171,182,189,212,223,194,201,248,243,238,229,
60,55,42,33,16,27,6,13,100,111,114,121,72,67,94,85,
1,10,23,28,45,38,59,48,89,82,79,68,117,126,99,104,
177,186,167,172,157,150,139,128,233,226,255,244,197,206,211,216,
122,113,108,103,86,93,64,75,34,41,52,63,14,5,24,19,
202,193,220,215,230,237,240,251,146,153,132,143,190,181,168,163}
local mul_13 = {[0]=0,13,26,23,52,57,46,35,104,101,114,127,92,81,70,75,
208,221,202,199,228,233,254,243,184,181,162,175,140,129,150,155,
187,182,161,172,143,130,149,152,211,222,201,196,231,234,253,240,
107,102,113,124,95,82,69,72,3,14,25,20,55,58,45,32,
109,96,119,122,89,84,67,78,5,8,31,18,49,60,43,38,
189,176,167,170,137,132,147,158,213,216,207,194,225,236,251,246,
214,219,204,193,226,239,248,245,190,179,164,169,138,135,144,157,
6,11,28,17,50,63,40,37,110,99,116,121,90,87,64,77,
218,215,192,205,238,227,244,249,178,191,168,165,134,139,156,145,
10,7,16,29,62,51,36,41,98,111,120,117,86,91,76,65,
97,108,123,118,85,88,79,66,9,4,19,30,61,48,39,42,
177,188,171,166,133,136,159,146,217,212,195,206,237,224,247,250,
183,186,173,160,131,142,153,148,223,210,197,200,235,230,241,252,
103,106,125,112,83,94,73,68,15,2,21,24,59,54,33,44,
12,1,22,27,56,53,34,47,100,105,126,115,80,93,74,71,
220,209,198,203,232,229,242,255,180,185,174,163,128,141,154,151}
local mul_14 = {[0]=0,14,28,18,56,54,36,42,112,126,108,98,72,70,84,90,
224,238,252,242,216,214,196,202,144,158,140,130,168,166,180,186,
219,213,199,201,227,237,255,241,171,165,183,185,147,157,143,129,
59,53,39,41,3,13,31,17,75,69,87,89,115,125,111,97,
173,163,177,191,149,155,137,135,221,211,193,207,229,235,249,247,
77,67,81,95,117,123,105,103,61,51,33,47,5,11,25,23,
118,120,106,100,78,64,82,92,6,8,26,20,62,48,34,44,
150,152,138,132,174,160,178,188,230,232,250,244,222,208,194,204,
65,79,93,83,121,119,101,107,49,63,45,35,9,7,21,27,
161,175,189,179,153,151,133,139,209,223,205,195,233,231,245,251,
154,148,134,136,162,172,190,176,234,228,246,248,210,220,206,192,
122,116,102,104,66,76,94,80,10,4,22,24,50,60,46,32,
236,226,240,254,212,218,200,198,156,146,128,142,164,170,184,182,
12,2,16,30,52,58,40,38,124,114,96,110,68,74,88,86,
55,57,43,37,15,1,19,29,71,73,91,85,127,113,99,109,
215,217,203,197,239,225,243,253,167,169,187,181,159,145,131,141}
local Rcon = {{0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00}, {0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00}, {0x20, 0x00, 0x00, 0x00}, {0x40, 0x00, 0x00, 0x00}, {0x80, 0x00, 0x00, 0x00},
    {0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00}}

local function mysplit (inputstr, sep)
    if sep == nil then
            sep = "%s"
    end
    local t={}
    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
            table.insert(t, str)
    end
    return t
end

local Nkt = {
    [16] = 4,
    [24] = 6,
    [32] = 8
}
local Nb = 4
local Nrt = {
    [16] = 10,
    [24] = 12,
    [32] = 14
}

local function base16ToBase10(n)
    local convo = {["0"]=0,["1"]=1,["2"]=2,["3"]=3,["4"]=4,["5"]=5,["6"]=6,["7"]=7,["8"]=8,["9"]=9,["a"]=10,["b"]=11,["c"]=12,["d"]=13,["e"]=14,["f"]=15}
    local out = 0
    for i = 1, #n do
        out = out + (convo[n:sub(i,i)] * 16 ^ (#n-i))
    end
    return out
end

local function base10ToBase16(n)
    local convo = {[0]="0",[1]="1",[2]="2",[3]="3",[4]="4",[5]="5",[6]="6",[7]="7",[8]="8",[9]="9",[10]="a",[11]="b",[12]="c",[13]="d",[14]="e",[15]="f"}
    local out = ""
    while n > 0 do
        out = convo[n%16] .. out
        n = math.floor(n/16)    
    end
    return out
end

local function StringToTable(str)
    local out = {}
    for i=1,#str do
        table.insert(out, str:sub(i,i):byte())
    end
    return out
end

local function TableToString(tbl)
    local out = ""
    for i=1,#tbl do
        out = out .. string.char(tbl[i])
    end
    return out
end

local function SubTable(tbl, start, endd)
    local out = {}
    for i=start,endd do
        table.insert(out, tbl[i])
    end
    return out
end

local function SubWord(word)
    local out = {SBox[word[1]], SBox[word[2]], SBox[word[3]], SBox[word[4]]}
    return out
end

local function RotWord(word)
    local rotatedWord = {word[2], word[3], word[4], word[1]}
    return rotatedWord
end

local function XorWord(word, word2)
    local out = {bit32.bxor(word[1], word2[1]), bit32.bxor(word[2], word2[2]), bit32.bxor(word[3], word2[3]), bit32.bxor(word[4], word2[4])}
    return out
end

local function KeyExpansion(key, Nk, Nr)
    local temp
    local words = {}
    for i=1, Nk do
        words[i] = {key[4*(i-1)+1], key[4*(i-1)+2], key[4*(i-1)+3], key[4*(i-1)+4]}
    end
    
    for i=Nk+1, Nb * (Nr+1) do
        temp = words[i-1]
        if (i-1) % Nk == 0 then
            temp = XorWord(SubWord(RotWord(temp)), Rcon[(i-1)/Nk])
        elseif (Nk > 6) and ((i-1) % Nk == 4) then
            temp = SubWord(temp)
        end
        words[i] = XorWord(words[i-Nk], temp)
    end
    return words
end

local function copyBlock(block)
    local out = {}
    for k,v in ipairs(block) do
        out[k] = v
    end
    return out
end

local function SubBytes(block)
    local newBlock = {
        {SBox[block[1][1]], SBox[block[1][2]], SBox[block[1][3]], SBox[block[1][4]]},
        {SBox[block[2][1]], SBox[block[2][2]], SBox[block[2][3]], SBox[block[2][4]]},
        {SBox[block[3][1]], SBox[block[3][2]], SBox[block[3][3]], SBox[block[3][4]]},
        {SBox[block[4][1]], SBox[block[4][2]], SBox[block[4][3]], SBox[block[4][4]]}
    }
    return newBlock
end

local function ShiftRows(block)
    local newBlock = {
        {block[1][1], block[1][2], block[1][3], block[1][4]},
        {block[2][2], block[2][3], block[2][4], block[2][1]},
        {block[3][3], block[3][4], block[3][1], block[3][2]},
        {block[4][4], block[4][1], block[4][2], block[4][3]}
    }
    return newBlock
end

local function Xor(...)
    local args = {...}
    local result = args[1]
    table.remove(args, 1)
    for k, v in ipairs(args) do
        result = bit32.bxor(result, v)
    end
    return result
end

local function MixColumns(block)
    local cols = {
        {block[1][1], block[2][1], block[3][1], block[4][1]},
        {block[1][2], block[2][2], block[3][2], block[4][2]},
        {block[1][3], block[2][3], block[3][3], block[4][3]},
        {block[1][4], block[2][4], block[3][4], block[4][4]}
    }
    local newCols = {}
    for k, v in ipairs(cols) do
        table.insert(newCols, {})
        newCols[k][1] = Xor(mul_2[v[1]], mul_3[v[2]], v[3], v[4])
        newCols[k][2] = Xor(v[1], mul_2[v[2]], mul_3[v[3]], v[4])
        newCols[k][3] = Xor(v[1], v[2], mul_2[v[3]], mul_3[v[4]])
        newCols[k][4] = Xor(mul_3[v[1]], v[2], v[3], mul_2[v[4]])
    end
    local newBlock = {
        {newCols[1][1], newCols[2][1], newCols[3][1], newCols[4][1]},
        {newCols[1][2], newCols[2][2], newCols[3][2], newCols[4][2]},
        {newCols[1][3], newCols[2][3], newCols[3][3], newCols[4][3]},
        {newCols[1][4], newCols[2][4], newCols[3][4], newCols[4][4]}
    }
    return newBlock
end

local function AddRoundKey(block, words, keyId)
    local cols = {
        {block[1][1], block[2][1], block[3][1], block[4][1]},
        {block[1][2], block[2][2], block[3][2], block[4][2]},
        {block[1][3], block[2][3], block[3][3], block[4][3]},
        {block[1][4], block[2][4], block[3][4], block[4][4]}
    }
    local roundKey = {}
    for i=4*(keyId-1)+1, 4*keyId do
        table.insert(roundKey, words[i])
    end
    for k, v in ipairs(cols) do
        cols[k] = XorWord(v, roundKey[k])
    end
    local newBlock = {
        {cols[1][1], cols[2][1], cols[3][1], cols[4][1]},
        {cols[1][2], cols[2][2], cols[3][2], cols[4][2]},
        {cols[1][3], cols[2][3], cols[3][3], cols[4][3]},
        {cols[1][4], cols[2][4], cols[3][4], cols[4][4]}
    }
    return newBlock
end

local function EncryptBlock(block, words, Nr)
    local state = copyBlock(block)
    state = AddRoundKey(state, words, 1)
    for round=1, Nr-1 do
        state = SubBytes(state)
        state = ShiftRows(state)
        state = MixColumns(state)
        state = AddRoundKey(state, words, round+1)
    end
    state = SubBytes(state)
    state = ShiftRows(state)
    state = AddRoundKey(state, words, Nr+1)
    return state
end

local function AES_Block(inp)
    local out = {
        {},
        {},
        {},
        {}
    }
    for x = 1, 4 do
        for y = 1, 4 do
            out[y][x] = inp[(x-1)*4+y]
        end
    end
    return out
end

local function AES_Encrypt(plaintext, key)
    if type(plaintext) ~= "table" then
        error("AES_Encrypt: bad argument #1 (expected table, got "..type(plaintext)..")")
    end
    for k,v in ipairs(plaintext) do
        if type(v) ~= "number" then
            error("AES_Encrypt: Invalid plaintext at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_Encrypt: Invalid plaintext at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if type(key) ~= "table" then
        error("AES_Encrypt: bad argument #2 (expected table, got "..type(key)..")")
    end
    for k,v in ipairs(key) do
        if type(v) ~= "number" then
            error("AES_Encrypt: Invalid key at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_Encrypt: Invalid key at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if #key > 32 then
        key = SubTable(key, 1, 32)
    end
    if Nkt[#key] == nil then
        error("AES_Encrypt: Key must be 16, 24, 32 characters long")
    end
    local blocks = {}
    for i=1, math.ceil(#plaintext/16) do
        table.insert(blocks, AES_Block(SubTable(plaintext, 16*(i-1)+1, 16*(i-1)+16)))
    end
    local words = KeyExpansion(key, Nkt[#key], Nrt[#key])
    for k,v in ipairs(blocks) do
        blocks[k] = EncryptBlock(v, words, Nrt[#key])
    end
    local out = {}
    for k,v in ipairs(blocks) do
        for x = 1, 4 do
            for y = 1, 4 do
                table.insert(out, v[y][x])
            end
        end
    end
    return out
end

local function InvShiftRows(block)
    local newBlock = {
        {block[1][1], block[1][2], block[1][3], block[1][4]},
        {block[2][4], block[2][1], block[2][2], block[2][3]},
        {block[3][3], block[3][4], block[3][1], block[3][2]},
        {block[4][2], block[4][3], block[4][4], block[4][1]}
    }
    return newBlock
end

local function InvSubBytes(block)
    local newBlock = {
        {InvSBox[block[1][1]], InvSBox[block[1][2]], InvSBox[block[1][3]], InvSBox[block[1][4]]},
        {InvSBox[block[2][1]], InvSBox[block[2][2]], InvSBox[block[2][3]], InvSBox[block[2][4]]},
        {InvSBox[block[3][1]], InvSBox[block[3][2]], InvSBox[block[3][3]], InvSBox[block[3][4]]},
        {InvSBox[block[4][1]], InvSBox[block[4][2]], InvSBox[block[4][3]], InvSBox[block[4][4]]}
    }
    return newBlock
end

local function InvMixColumns(block)
    local cols = {
        {block[1][1], block[2][1], block[3][1], block[4][1]},
        {block[1][2], block[2][2], block[3][2], block[4][2]},
        {block[1][3], block[2][3], block[3][3], block[4][3]},
        {block[1][4], block[2][4], block[3][4], block[4][4]}
    }
    local newCols = {}
    for k, v in ipairs(cols) do
        table.insert(newCols, {})
        newCols[k][1] = Xor(mul_14[v[1]], mul_11[v[2]], mul_13[v[3]], mul_9[v[4]])
        newCols[k][2] = Xor(mul_9[v[1]], mul_14[v[2]], mul_11[v[3]], mul_13[v[4]])
        newCols[k][3] = Xor(mul_13[v[1]], mul_9[v[2]], mul_14[v[3]], mul_11[v[4]])
        newCols[k][4] = Xor(mul_11[v[1]], mul_13[v[2]], mul_9[v[3]], mul_14[v[4]])
    end
    local newBlock = {
        {newCols[1][1], newCols[2][1], newCols[3][1], newCols[4][1]},
        {newCols[1][2], newCols[2][2], newCols[3][2], newCols[4][2]},
        {newCols[1][3], newCols[2][3], newCols[3][3], newCols[4][3]},
        {newCols[1][4], newCols[2][4], newCols[3][4], newCols[4][4]}
    }
    return newBlock
end

local function DecryptBlock(block, words, Nr)
    local state = copyBlock(block)
    state = AddRoundKey(state, words, Nr+1)
    for round=Nr-1, 1, -1 do
        state = InvShiftRows(state)
        state = InvSubBytes(state)
        state = AddRoundKey(state, words, round+1)
        state = InvMixColumns(state)
    end
    state = InvShiftRows(state)
    state = InvSubBytes(state)
    state = AddRoundKey(state, words, 1)
    return state
end

local function AES_Decrypt(ciphertext, key)
    if type(ciphertext) ~= "table" then
        error("AES_Decrypt: bad argument #1 (expected table, got "..type(ciphertext)..")")
    end
    for k,v in ipairs(ciphertext) do
        if type(v) ~= "number" then
            error("AES_Decrypt: Invalid ciphertext at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_Decrypt: Invalid ciphertext at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if type(key) ~= "table" then
        error("AES_Decrypt: bad argument #2 (expected table, got "..type(key)..")")
    end
    for k,v in ipairs(key) do
        if type(v) ~= "number" then
            error("AES_Decrypt: Invalid key at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_Decrypt: Invalid key at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if #key > 32 then
        key = SubTable(key, 1, 32)
    end
    if Nkt[#key] == nil then
        error("AES_Decrypt: Key must be 16, 24, 32 characters long")
    end
    local blocks = {}
    for i=1, math.ceil(#ciphertext/16) do
        table.insert(blocks, AES_Block(SubTable(ciphertext, 16*(i-1)+1, 16*(i-1)+16)))
    end
    local words = KeyExpansion(key, Nkt[#key], Nrt[#key])
    for k,v in ipairs(blocks) do
        blocks[k] = DecryptBlock(v, words, Nrt[#key])
    end
    local out = {}
    for k,v in ipairs(blocks) do
        for x = 1, 4 do
            for y = 1, 4 do
                table.insert(out, v[y][x])
            end
        end
    end
    return out
end

local function StringToBytes(str)
    local out = {}
    for i=1,#str do
        table.insert(out, str:sub(i,i):byte())
    end
    return out
end

local function InvertString(str)
    local function rawInvert(iStr)
        local out = ""
        for i=#iStr, 1, -1 do
            out = out .. iStr:sub(i,i)
        end
        return out
    end
    if str:match("e") == nil then
        return rawInvert(str)
    else
        local firstp = "[" .. mysplit(str, ".")[1] .. ".]"
        str = str:gsub(firstp, "")
        local secondp = "[e" .. mysplit(str, "e")[2] .. "]"
        str = str:gsub(secondp, "")
        str = rawInvert(str)
        str = firstp:gsub("[[]", ""):gsub("[]]", "") .. str .. secondp:gsub("[[]", ""):gsub("[]]", "")
        return str
    end
end

local function BytesToHexString(tbl)
    local out = ""
    for i=1,#tbl do
        out = out .. base10ToBase16(tbl[i])
    end
    return out
end

local function ASH_Hash(plaintext, rounds, salt, len)
    plaintext = StringToBytes(plaintext)
    for round=0, rounds-1 do
        if round % 2 ~= 0 then
            for i=1, #plaintext do
                plaintext[i] = plaintext[i] + (plaintext[i+1] ~= nil and plaintext[i+1] or plaintext[1]) + salt
            end
        else
            for i=1, #plaintext do
                plaintext[i] = math.floor(tonumber(InvertString(tostring(plaintext[i]))))
            end
            for i=#plaintext, 1, -1 do
                plaintext[i] = plaintext[i] + (plaintext[i-1] ~= nil and plaintext[i-1] or plaintext[#plaintext]) + salt
            end
        end
    end
    local out = BytesToHexString(plaintext)
    while #out < len do
        out = out .. out
    end
    if #out > len then
        out = out:sub(1, len)
    end

    return out
end

local function StringToKey(str, salt)
    if type(str) ~= "string" then
        error("StringToKey: bad argument #1 (expected string, got "..type(str)..")")
    end
    if type(salt) ~= "number" then
        error("StringToKey: bad argument #2 (expected number, got "..type(salt)..")")
    end
    local hash = ASH_Hash(str, 32, salt, 32)
    local key = {}
    for i=1,#hash do
        table.insert(key, hash:sub(i,i):byte())
    end
    return key
end

local function GenerateRandomKey()
    local keyCache = {}
    local key = {}
    for i=1, 32 do
        local rand = 0
        while (rand == 0) or (keyCache[rand] ~= nil) do
            rand = math.random(1, 255)
        end
        keyCache[rand] = true
        table.insert(key, rand)
    end
    return key
end

local function XorBlock(block1, block2)
    local out = copyBlock(block1)
    for y=1,4 do
        for x=1,4 do
            out[y][x] = Xor(out[y][x], block2[y][x])
        end
    end
    return out
end

local function AES_EncryptCBC(plaintext, key, iv)
    if type(plaintext) ~= "table" then
        error("AES_EncryptCBC: bad argument #1 (expected table, got "..type(plaintext)..")")
    end
    for k,v in ipairs(plaintext) do
        if type(v) ~= "number" then
            error("AES_EncryptCBC: Invalid plaintext at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_EncryptCBC: Invalid plaintext at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if type(key) ~= "table" then
        error("AES_EncryptCBC: bad argument #2 (expected table, got "..type(key)..")")
    end
    for k,v in ipairs(key) do
        if type(v) ~= "number" then
            error("AES_EncryptCBC: Invalid key at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_EncryptCBC: Invalid key at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if #key > 32 then
        key = SubTable(key, 1, 32)
    end
    if Nkt[#key] == nil then
        error("AES_EncryptCBC: Key must be 16, 24, 32 characters long")
    end
    if type(iv) ~= "table" then
        error("AES_EncryptCBC: bad argument #3 (expected table, got "..type(iv)..")")
    end
    for k,v in ipairs(iv) do
        if type(v) ~= "number" then
            error("AES_EncryptCBC: Invalid iv at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_EncryptCBC: Invalid iv at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if #iv > 16 then
        iv = SubTable(iv, 1, 16)
    end
    if #iv ~= 16 then
        error("AES_EncryptCBC: Iv must be 16 characters long")
    end
    local blocks = {}
    table.insert(blocks, AES_Block(iv))
    for i=1, math.ceil(#plaintext/16) do
        table.insert(blocks, AES_Block(SubTable(plaintext, 16*(i-1)+1, 16*(i-1)+16)))
    end
    local words = KeyExpansion(key, Nkt[#key], Nrt[#key])
    for i=2,#blocks do
        blocks[i] = XorBlock(blocks[i], blocks[i-1])
        blocks[i] = EncryptBlock(blocks[i], words, Nrt[#key])
    end
    local out = {}
    table.remove(blocks, 1)
    for k,v in ipairs(blocks) do
        for x = 1, 4 do
            for y = 1, 4 do
                table.insert(out, v[y][x])
            end
        end
    end
    return out
end

local function AES_DecryptCBC(ciphertext, key, iv)
    if type(ciphertext) ~= "table" then
        error("AES_DecryptCBC: bad argument #1 (expected table, got "..type(ciphertext)..")")
    end
    for k,v in ipairs(ciphertext) do
        if type(v) ~= "number" then
            error("AES_DecryptCBC: Invalid ciphertext at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_DecryptCBC: Invalid ciphertext at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if type(key) ~= "table" then
        error("AES_DecryptCBC: bad argument #2 (expected table, got "..type(key)..")")
    end
    for k,v in ipairs(key) do
        if type(v) ~= "number" then
            error("AES_DecryptCBC: Invalid key at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_DecryptCBC: Invalid key at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if #key > 32 then
        key = SubTable(key, 1, 32)
    end
    if Nkt[#key] == nil then
        error("AES_DecryptCBC: Key must be 16, 24, 32 characters long")
    end
    if type(iv) ~= "table" then
        error("AES_DecryptCBC: bad argument #3 (expected table, got "..type(iv)..")")
    end
    for k,v in ipairs(iv) do
        if type(v) ~= "number" then
            error("AES_DecryptCBC: Invalid iv at "..k.." (expected number (0-255), got "..type(v)..")")
        end
        if (v < 0) or (v > 255) then
            error("AES_DecryptCBC: Invalid iv at "..k.." (expected number (0-255), got "..v..")")
        end
    end
    if #iv > 16 then
        iv = SubTable(iv, 1, 16)
    end
    if #iv ~= 16 then
        error("AES_DecryptCBC: Iv must be 16 characters long")
    end
    local pblocks = {}
    local blocks = {}
    table.insert(pblocks, AES_Block(iv))
    table.insert(blocks, AES_Block(iv))
    for i=1, math.ceil(#ciphertext/16) do
        table.insert(blocks, AES_Block(SubTable(ciphertext, 16*(i-1)+1, 16*(i-1)+16)))
        table.insert(pblocks, AES_Block(SubTable(ciphertext, 16*(i-1)+1, 16*(i-1)+16)))
    end
    local words = KeyExpansion(key, Nkt[#key], Nrt[#key])
    for i=2,#blocks do
        blocks[i] = DecryptBlock(blocks[i], words, Nrt[#key])
        blocks[i] = XorBlock(blocks[i], pblocks[i-1])
    end
    local out = {}
    table.remove(blocks, 1)
    for k,v in ipairs(blocks) do
        for x = 1, 4 do
            for y = 1, 4 do
                table.insert(out, v[y][x])
            end
        end
    end
    return out
end

return {
    Encrypt = AES_Encrypt,
    Decrypt = AES_Decrypt,
    EncryptCBC = AES_EncryptCBC,
    DecryptCBC = AES_DecryptCBC,
    StringToKey = StringToKey,
    GenerateRandomKey = GenerateRandomKey,
    StringToTable = StringToTable,
    TableToString = TableToString
}
