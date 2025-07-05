package cc.madefor.phoenix.ccsecureboot.mixin;

import dan200.computercraft.shared.computer.core.ServerContext;
import net.minecraft.world.level.storage.LevelResource;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

@Mixin(ServerContext.class)
public interface ServerContextAccessor {
    @Accessor("FOLDER")
    static LevelResource getFolder() {
        throw new AssertionError();
    }
}
