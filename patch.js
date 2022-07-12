const fs = require("fs")
const path = require("path")

const assert = (v, msg = "") => {
    if (!v) {
        console.error(`Assertion error: ${msg}`)
        process.exit(-1)
    }
}

Object.defineProperty(Object.prototype, "let", { value(fn) { return fn(this) }, configurable: true, writable: true })

const src = "./UserAssembly.dll"
const buf = fs.readFileSync(src)
let ptr, pattern
assert(
    buf.readUInt16LE() === 0x5A4D
    && buf.readUInt32LE(ptr = buf.readUInt16LE(0x3C)) === 0x4550
    && buf.readUInt16LE(ptr += 4) === 0x8664
    && buf.readUInt16LE(ptr += 20) === 0x20B,
    "Invalid file"
)

const bStr = buf.toString("latin1")

// RegionConfigDecryptAndVerify
// Better way:
// At call SimpleJSON_Parse block (18156C328, VER: 2.7.50, C32: 05B243AF)
// 33 D2             xor     edx, edx
// 48 8B CB          mov     rcx, rbx
// E8 2E 41 90 03    call    System_Convert$$FromBase64String
// C3                retn
// 90                nop
// 90                nop
// pattern = /\x48\x8B\xCB\xE8[\x00-\xFF]{4}\x48\x8B\xD8\x33\xD2\x48\x8B\xC8\xE8[\x00-\xFF]{4}\x48\x8B\xF8\x33\xD2\x48\x8B\xCE\xE8[\x00-\xFF]{4}\x45\x33\xC0\x48\x8B\xD0\x48\x8B\xCF\xE8[\x00-\xFF]{4}/g
//
// DO IT BY YOURSELF:
// call Decrypt -> NOP
// test !VerifyData; jz error -> NOP


// GetPlayerTokenReq - EncryptGeneratedRndSeed
// pattern = /\x33\xD2\x48\x8B\xCB\xE8[\x00-\xFF]{4}\x33\xD2\x48\x8B\xC8\xE8[\x00-\xFF]{4}\x48\x8B\xD8\x48\x8B\x0D[\x00-\xFF]{4}/g
// 
// DO IT BY YOURSELF:
// call Encrypt -> NOP


// GetPlayerTokenRsp - LoginSeedVerify
// pattern = /\x33\xD2\x48\x8B\xCB\xE8[\x00-\xFF]{4}\x48\x8B\xD8\x33\xD2\x48\x8B\xCF\xE8[\x00-\xFF]{4}\x45\x33\xC0\x48\x8B\xD0\x48\x8B\xCB\xE8[\x00-\xFF]{4}/g
// 
// DO IT BY YOURSELF:
// call Decrypt -> NOP
// test !VerifyData; jz error -> NOP

// miHuYoSDK - RSAEncrypt
// pattern = /\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xEC\x20\x48\x8B\xF9\x48\x8B\xF2\x48\x8B\x0D[\x00-\xFF]{4}\xE8[\x00-\xFF]{4}\x33\xD2\x48\x8B\xC8\x48\x8B\xD8\xE8[\x00-\xFF]{4}\x48\x85\xDB\x0F/g
//
// DO IT BY YOURSELF:
// sub rsp, 20h -> NOP
// Add mov rax, rdx
// Add mov rbp, rsp
// Add pop rbp; retn
// align

//  MoleMole.Miscs.GetGlobalDispatchUrl
//  48 ?? ?? ?? ?? ?? ?? 45 33 C9 48 8B ?? ?? ?? ?? ?? 48 8B C8 4C 8B ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ??
pattern = /\x48[\x00-\xFF]{6}\x45\x33\xC9\x48\x8B[\x00-\xFF]{5}\x48\x8B\xC8\x4C\x8B[\x00-\xFF]{5}\x48[\x00-\xFF]{6}\xE8[\x00-\xFF]{4}/g
pattern.exec(bStr).let(result => {
    const s = result.index
    const e = pattern.lastIndex
    buf.fill(0x90, s, e)   // NOP
})

fs.writeFileSync(`${path.dirname(src)}${path.sep}UserAssembly-patched.dll`, buf)