package cc.madefor.phoenix.ccsecureboot.forge;

import cc.madefor.phoenix.ccsecureboot.CCSecureBoot;
import net.minecraftforge.fml.common.Mod;
import net.minecraftforge.fml.javafmlmod.FMLJavaModLoadingContext;

@Mod(CCSecureBoot.MOD_ID)
public class CCSecureBootForge {
    public CCSecureBootForge() {
        CCSecureBoot.init();
    }
}