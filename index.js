import { Setting, SettingsObject } from "SettingsManager/SettingsManager"

const Base64 = Java.type("java.util.Base64")
const Cipher = Java.type("javax.crypto.Cipher")
const IvParameterSpec = Java.type("javax.crypto.spec.IvParameterSpec")
const SecretKeySpec = Java.type("javax.crypto.spec.SecretKeySpec")
const C01PacketChatMessage = Java.type("net.minecraft.network.play.client.C01PacketChatMessage")

var PrivateChat = {
    cipherTransformation: "AES/CBC/PKCS5PADDING",
    aesEncryptionAlgorithem: "AES",
    err: null,

    s: function(x) {
        return x.charCodeAt(0)
    },
    t: function(x) {
        return String.fromCharCode(x)
    },

    expandName: function(name) {
        var expanded = name.trim()
        for (var i = name.trim().length; i < 16; i++) {
            expanded += "0"
        }
        return expanded
    },

    sendMessage: function(text) {
        var toSend =  text.trim() + "|"
        if (toSend.length < 256) {
            var packet = new C01PacketChatMessage(toSend)
            Player.getPlayer().field_71174_a.func_147297_a(packet)
        } else {
            ChatLib.chat("Error sending message. Encrypted message is longer than 256 chars")
        }
    },

    createWatermark: function(category, encryptedText) {
        if (!this.settings.getSetting("PrivateChat", "Show Watermark")) {
            return ""
        }

        if (this.err !== null) {
            textComponent = new TextComponent("&4\u25A0")
                        .setHoverValue(this.err)
            this.err = null
            return textComponent
        }
        if (this.settings.getSetting(category, "Show Encrypted Text")) {
            return new TextComponent("&8\u25A0")
                        .setHoverValue(
                            "&7This message was encrypted\n\n" +
                            "&8Encrypted Text:\n" +
                            encryptedText.slice(0, encryptedText.length - 1)
                        )
        } else {
            return new TextComponent("&8\u25A0")
                        .setHoverValue("&7This message was encrypted")
        }
    },

    encrypt: function(plainText, encryptionKey) {
        var encryptedText = ""
        try {
            var cipher = Cipher.getInstance(this.cipherTransformation)
            var key = encryptionKey.split('').map(this.s)
            var secretKey = new SecretKeySpec(key, this.aesEncryptionAlgorithem)
            var ivparameterspec = new IvParameterSpec(key)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivparameterspec)
            var cipherText = cipher.doFinal(plainText.split('').map(this.s))
            var encoder = Base64.getEncoder()
            encryptedText = encoder.encodeToString(cipherText)
        } catch(err) {
            ChatLib.chat("Encrypt Exception: " + err.message)
        }
        return encryptedText
    },

    decrypt: function(encryptedText, encryptionKey) {
        var decryptedText = ""
        try {
            var cipher = Cipher.getInstance(this.cipherTransformation)
            var key = encryptionKey.split('').map(this.s)
            var secretKey = new SecretKeySpec(key, this.aesEncryptionAlgorithem)
            var ivparameterspec = new IvParameterSpec(key)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivparameterspec)
            var decoder = Base64.getDecoder()
            var cipherText = decoder.decode(encryptedText.split('').map(this.s))
            var final = cipher.doFinal(cipherText)
            for(var i = 0; i < final.length; i++) {
                decryptedText += this.t(final[i])
            }
        } catch (err) {
            this.err = "Decrypt Exception : " + err.message
            decryptedText = encryptedText
        }
        return decryptedText;
    },

    settings: new SettingsObject("PrivateChat", [
        {
            name: "PrivateChat",
            settings: [
                new Setting.Toggle("Global Toggle", true),
                new Setting.Toggle("Show Watermark", true),
                new Setting.Button("Reset Settings", "click", function() {
                    PrivateChat.settings.reset()
                    PrivateChat.settings.load()
                })
            ]
        }, {
            name: "Guild",
            settings: [
                new Setting.Toggle("Encrypt Guild Chat", true),
                new Setting.Toggle("Decrypt Guild Chat", true),
                new Setting.Toggle("Print Decrypted Chat", false),
                new Setting.Toggle("Show Encrypted Text", true)
            ]
        }, {
            name: "Party",
            settings: [
                new Setting.Toggle("Encrypt Party Chat", true),
                new Setting.Toggle("Decrypt Party Chat", true),
                new Setting.Toggle("Print Decrypted Chat", false),
                new Setting.Toggle("Show Encrypted Text", true)
            ]
        }, {
            name: "Co-op",
            settings: [
                new Setting.Toggle("Encrypt Co-op Chat", true),
                new Setting.Toggle("Decrypt Co-op Chat", true),
                new Setting.Toggle("Print Decrypted Chat", false),
                new Setting.Toggle("Show Encrypted Text", true)
            ]
        }, {
            name: "Private",
            settings: [
                new Setting.Toggle("Encrypt Private Chat", true),
                new Setting.Toggle("Decrypt Private Chat", true),
                new Setting.Toggle("Print Decrypted Chat", false),
                new Setting.Toggle("Show Encrypted Text", true)
            ]
        }, {
            name: "All",
            settings: [
                new Setting.Toggle("Encrypt All Chat", true),
                new Setting.Toggle("Decrypt All Chat", true),
                new Setting.Toggle("Print Decrypted Chat", false),
                new Setting.Toggle("Show Encrypted Text", true)
            ]
        }
    ])
}

PrivateChat.settings.setCommand("PrivateChat").setSize(300, 100)
Setting.register(PrivateChat.settings)

register("command", function() {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")
    || !PrivateChat.settings.getSetting("Guild", "Encrypt Guild Chat")) {
        ChatLib.command("/gchat " + [].slice.call(arguments).join(" "))
        return
    }

    PrivateChat.sendMessage(
        "/gchat " +
        PrivateChat.encrypt(
            [].slice.call(arguments).join(" "),
            PrivateChat.expandName(Player.getName())
        )
    )
}).setName("gchat");

register("command", function() {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")
    || !PrivateChat.settings.getSetting("Party", "Encrypt Party Chat")) {
        ChatLib.command("/pchat " + [].slice.call(arguments).join(" "))
        return
    }

    PrivateChat.sendMessage(
        "/pchat " +
        PrivateChat.encrypt(
            [].slice.call(arguments).join(" "),
            PrivateChat.expandName(Player.getName())
        )
    )
}).setName("pchat")

register("command", function() {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")
    || !PrivateChat.settings.getSetting("Co-op", "Encrypt Co-op Chat")) {
        ChatLib.command("/cchat " + [].slice.call(arguments).join(" "))
        return
    }

    PrivateChat.sendMessage(
        "/cchat " +
        PrivateChat.encrypt(
            [].slice.call(arguments).join(" "),
            PrivateChat.expandName(Player.getName())
        )
    )
}).setName("cchat")

register("command", function() {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")
    || !PrivateChat.settings.getSetting("All", "Encrypt All Chat")) {
        ChatLib.command("/achat " + [].slice.call(arguments).join(" "))
        return
    }

    PrivateChat.sendMessage(
        "/achat " +
        PrivateChat.encrypt(
            [].slice.call(arguments).join(" "),
            PrivateChat.expandName(Player.getName())
        )
    )
}).setName("achat")

register("command", function() {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")
    || !PrivateChat.settings.getSetting("Private", "Encrypt Private Chat")) {
        ChatLib.command("/w " + [].slice.call(arguments).join(" "))
        return
    }

    args = [].slice.call(arguments)
    name = args.shift()

    PrivateChat.sendMessage(
        '/w ' + name + ' ' +
        PrivateChat.encrypt(
            args.join(" "),
            PrivateChat.expandName(name.toLowerCase())
        )
    )
}).setName("w")

register("chat", (name, text, event) => {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")) return
    if (!text.endsWith("|")) return

    var decryptedText = PrivateChat.decrypt(
        text.slice(0, text.length - 1),
        PrivateChat.expandName(ChatLib.removeFormatting(name.replace(/ *\[[^\]]*\] */g, "")))
    )

    if (PrivateChat.settings.getSetting("Party", "Decrypt Party Chat")) {
        cancel(event)
        new Message(
            "&r&9Party &8> " + name + ": &r" + decryptedText,
            PrivateChat.createWatermark("Party", PrivateChat.err === null ? text : PrivateChat.err)
        ).chat()

        PrivateChat.err = null
    }

    if (PrivateChat.settings.getSetting("Party", "Print Decrypted Chat")) {
        print("Party &8> " + ChatLib.removeFormatting(name) + ": " + decryptedText)
    }
}).setCriteria("&r&9Party &8> ${name}: &r${text}&r")

register("chat", (name, text, event) => {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")) return
    if (!text.endsWith("|")) return

    var decryptedText = PrivateChat.decrypt(
        text.slice(0, text.length - 1),
        PrivateChat.expandName(ChatLib.removeFormatting(name.replace(/ *\[[^\]]*\] */g, "")))
    )

    if (PrivateChat.settings.getSetting("Guild", "Decrypt Guild Chat")) {
        cancel(event)
        new Message(
            "&r&2Guild > " + name + ": &r" + decryptedText,
            PrivateChat.createWatermark("Guild", text)
        ).chat()
    }

    if (PrivateChat.settings.getSetting("Guild", "Print Decrypted Chat")) {
        print("Guild > " + ChatLib.removeFormatting(name) + ": " + decryptedText)
    }
}).setCriteria("&r&2Guild > ${name}: &r${text}&r")

register("chat", (name, text, event) => {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")) return
    if (!text.endsWith("|")) return

    var decryptedText = PrivateChat.decrypt(
        text.slice(0, text.length - 1),
        PrivateChat.expandName(ChatLib.removeFormatting(name.replace(/ *\[[^\]]*\] */g, "")))
    )

    if (PrivateChat.settings.getSetting("Co-op", "Decrypt Co-op Chat")) {
        cancel(event)
        new Message(
            "&r&bCo-op > " + name + ": &r" + decryptedText,
            PrivateChat.createWatermark("Co-op", text)
        ).chat()
    }

    if (PrivateChat.settings.getSetting("Co-op", "Print Decrypted Chat")) {
        print("Co-op > " + ChatLib.removeFormatting(name) + ": " + decryptedText)
    }
}).setCriteria("&r&bCo-op > ${name}: &r${text}&r")

// all chat
register("chat", (name, text, event) => {
    if (name.split(" ").length > 2) {
        return
    }
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")) return
    if (!text.endsWith("|")) return

    var decryptedText = PrivateChat.decrypt(
        text.slice(0, text.length - 1),
        PrivateChat.expandName(ChatLib.removeFormatting(name.replace(/ *\[[^\]]*\] */g, "")))
    )

    if (PrivateChat.settings.getSetting("All", "Decrypt All Chat")) {
        cancel(event)
        new Message(
            "&r" + name + ": &r" + decryptedText,
            PrivateChat.createWatermark("All", text)
        ).chat()
    }

    if (PrivateChat.settings.getSetting("All", "Print Decrypted Chat")) {
        print(ChatLib.removeFormatting(name) + ": " + decryptedText)
    }
}).setCriteria("&r${name}&r&f: ${text}&r")

// non-don all chat
register("chat", (name, text, event) => {
    if (name.split(" ").length > 1) return
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")) return
    if (!text.endsWith("|")) return

    var decryptedText = PrivateChat.decrypt(
        text.slice(0, text.length - 1),
        PrivateChat.expandName(ChatLib.removeFormatting(name.replace(/ *\[[^\]]*\] */g, "")))
    )

    if (PrivateChat.settings.getSetting("All", "Decrypt All Chat")) {
        cancel(event)
        new Message(
            "&r" + name + ": &r" + decryptedText,
            PrivateChat.createWatermark("All", text)
        ).chat()
    }

    if (PrivateChat.settings.getSetting("All", "Print Decrypted Chat")) {
        print(ChatLib.removeFormatting(name) + ": " + decryptedText)
    }
}).setCriteria("&r${name}&r&7: ${text}&r")


register("chat", (side, name, text, event) => {
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")) return
    if (!text.endsWith("|")) return

    var ename = ChatLib.removeFormatting(name.replace(/ *\[[^\]]*\] */g, ""))
    if(side.indexOf('From') == 0) {
        ename = Player.getName()
    }

    var decryptedText = PrivateChat.decrypt(
        ChatLib.removeFormatting(text.slice(0, text.length - 1)),
        PrivateChat.expandName(ename.toLowerCase())
    )

    if (PrivateChat.settings.getSetting("Private", "Decrypt Private Chat")) {
        cancel(event)
        new Message(
            "&dPM &5" + (side.includes('To') ? '>' : '<') + " " + name + ": &r&7" + decryptedText,
            PrivateChat.createWatermark("Private", text)
        ).chat()
    }

    if (PrivateChat.settings.getSetting("Private", "Print Decrypted Chat")) {
        print("&dPM" + (side.includes('To') ? '>' : '<') + " " + ChatLib.removeFormatting(name) + ": " + decryptedText)
    }
}).setCriteria("&d${side} &r${name}: &r${text}&r")

// skyblock island all chat
// thanks to Azael#0315 for this fix
register("chat", (name, text, event) => {
    if (name.split(" ").length > 3) {
        return
    }
    if (!PrivateChat.settings.getSetting("PrivateChat", "Global Toggle")) return
    if (!text.endsWith("|")) return

    var decryptedText = PrivateChat.decrypt(
        text.slice(0, text.length - 1),
        PrivateChat.expandName(ChatLib.removeFormatting(name.replace(/ *\[[^\]]*\] */g, "")))
    )

    if (PrivateChat.settings.getSetting("All", "Decrypt All Chat")) {
        cancel(event)
        new Message(
            "&r" + name + ": &r" + decryptedText,
            PrivateChat.createWatermark("All", text)
        ).chat()
    }

    if (PrivateChat.settings.getSetting("All", "Print Decrypted Chat")) {
        print(ChatLib.removeFormatting(name) + ": " + decryptedText)
    }
}).setCriteria("&r${name}&r&f: ${text}&r")

