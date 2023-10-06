copybin:
        if not exist bin\$(BUILD_ALT_DIR) (md bin\$(BUILD_ALT_DIR) )
        if exist $(OBJ_PATH)\$(O)\$(TARGETNAME).exe copy $(OBJ_PATH)\$(O)\$(TARGETNAME).exe bin\$(BUILD_ALT_DIR)
        if exist $(OBJ_PATH)\$(O)\$(TARGETNAME).pdb copy $(OBJ_PATH)\$(O)\$(TARGETNAME).pdb bin\$(BUILD_ALT_DIR)
