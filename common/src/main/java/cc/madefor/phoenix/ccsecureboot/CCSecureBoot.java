package cc.madefor.phoenix.ccsecureboot;

import dan200.computercraft.api.ComputerCraftAPI;
import dan200.computercraft.api.lua.IComputerSystem;
import dan200.computercraft.api.lua.ILuaAPI;
import dan200.computercraft.api.lua.ILuaAPIFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jspecify.annotations.Nullable;

import java.nio.file.Path;

public class CCSecureBoot implements ILuaAPIFactory {
	public static final String MOD_ID = "ccsecureboot";
	public static final Logger LOG = LogManager.getLogger(MOD_ID);

	public static void init() {
		ComputerCraftAPI.registerAPIFactory(new CCSecureBoot());
	}

	@Override
	public @Nullable ILuaAPI create(IComputerSystem computer) {
		return new CCSecureBootAPI(computer);
	}
}