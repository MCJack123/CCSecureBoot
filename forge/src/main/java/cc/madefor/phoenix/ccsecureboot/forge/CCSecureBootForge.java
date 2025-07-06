package cc.madefor.phoenix.ccsecureboot.forge;

import cc.madefor.phoenix.ccsecureboot.CCSecureBoot;
import net.neoforged.fml.common.Mod;

@Mod(CCSecureBoot.MOD_ID)
public class CCSecureBootForge {
    public CCSecureBootForge() {
        CCSecureBoot.init();
    }
}