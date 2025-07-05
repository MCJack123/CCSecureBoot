package cc.madefor.phoenix.ccsecureboot.fabric;

import cc.madefor.phoenix.ccsecureboot.CCSecureBoot;
import dan200.computercraft.api.ComputerCraftAPI;
import net.fabricmc.api.ModInitializer;

public class CCSecureBootFabric implements ModInitializer {
    @Override
    public void onInitialize() {
        CCSecureBoot.init();
    }
}