//
//  rmsigchks.swift
//  Fugu
//
//  Created by Linus Henze on 14.10.19.
//  Copyright © 2019/2020 Linus Henze. All rights reserved.
//

import Foundation

func rmsigchks_patchesFor(device: Int) -> [UInt64: [UInt8]] {
    switch device {
    case 0x8960:
        return [
            0x1000054e4: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
            0x1000054b4: [
                0x21, 0x00, 0x80, 0x52, // mov w1, 1
                0xE1, 0x9F, 0x02, 0x39, // strb w1, [sp,#0xA7]
                0x1F, 0x20, 0x03, 0xD5, // nop
                0xE1, 0xA7, 0x02, 0x39, // strb w1, [sp,#0xA9]
                0xE1, 0xAB, 0x02, 0x39, // strb w1, [sp,#0xAA]
                0x1F, 0x20, 0x03, 0xD5, // nop
                0x1F, 0x20, 0x03, 0xD5, // nop
                0x1F, 0x20, 0x03, 0xD5, // nop
                0x1F, 0x20, 0x03, 0xD5, // nop
            ]
        ]
    case 0x8000:
		return [
			0x10000792c: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
			0x10000791c: [
				0x21, 0x00, 0x80, 0x52, // mov w1, #0x1
				0xE1, 0x43, 0x01, 0xB9, // str w1, [sp, #0x140]
				0x1F, 0x20, 0x03, 0xD5, // nop
			]							// If this doesn't work, try 'noping a few more instructions. Look for (sp +) 0x142, 0x130, 0x138, 0xD0.
		] 								// 0x140 -> 0x10007ca0
			
    case 0x8010:
        return [
            0x100006ca8: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
            0x100006c80: [
                0x21, 0x00, 0x80, 0x52, // mov w1, 1
                0xE1, 0xE7, 0x03, 0x39, // strb w1, [sp, #0xf9]
                0xE1, 0xEF, 0x03, 0x39, // strb w1, [sp, #0xfb]
                0xE1, 0xF7, 0x03, 0x39, // strb w1, [sp, #0xfd]
                0x1F, 0x20, 0x03, 0xD5, // nop
                0x1F, 0x20, 0x03, 0xD5, // nop
                0x1F, 0x20, 0x03, 0xD5, // nop
                0x1F, 0x20, 0x03, 0xD5, // nop
                0x1F, 0x20, 0x03, 0xD5, // nop
            ]
        ]
        
    case 0x8011:
        return [
            0x100006df8: [
                0x21, 0x00, 0x80, 0x52, // movz w1, #0x1
                0xE1, 0xB7, 0x03, 0x39, // strb w1, [sp, #0xed]
                0xE1, 0xB3, 0x03, 0x39, // strb w1, [sp, #0xec]
                0xE1, 0xBB, 0x03, 0x39, // strb w1, [sp, #0xee]
            ],
            0x100006e0c: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
            0x100006e10: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
            0x100006e14: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
            0x10000f2d0: [
                0x00, 0x00, 0x80, 0xD2, // movz x0, #0
                0xC0, 0x03, 0x5f, 0xD6, // ret
            ]
        ]
	
	case 0x8015:
		return [
			0x100006868: [
				0x21, 0x00, 0x80, 0x52, // movz w1, #0x1
				0xe1, 0x97, 0x04, 0x39, // strb w1, [sp, #0x125]
				0xe1, 0x93, 0x04, 0x39, // strb w1, [sp, #0x124]
				0xe1, 0x9b, 0x04, 0x39, // strb w1, [sp, #0x126]
			],
			0x10000687c: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
			0x100006880: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
			0x100006884: [ 0x1F, 0x20, 0x03, 0xD5 ], // nop
			0x10000d2e4: [
				0x00, 0x00, 0x80, 0xD2, // movz x0, #0
                0xC0, 0x03, 0x5f, 0xD6, // ret
			]
		]
        
    default:
        return [:]
    }
}

class RmSigChksModule: CommandLineModule {
    static var name: String = "rmsigchks"
    static var description: String = "Disable signature checking in the SecureROM of a device.\nCurrently supports: t8010, t8011 (s8000 experimental).\nDevice will be pwned if it is not already."
    
    static var requiredArguments: [CommandLineArgument] = [
        // None
    ]
    
    static var optionalArguments: [CommandLineArgument] = [
        CommandLineArgument(shortVersion: "-e", longVersion: "--ecid", description: "The ECID of the device. Will use the first device found if unset.", type: .String),
    ]
    
    static func main(arguments args: ParsedArguments) -> Never {
        var ecid: String? = nil
        
        for i in args.optionalArguments {
            if i.shortVersion == "-e" {
                ecid = (i.value as! String)
                if ecid!.range(of: "^[0-9a-fA-F]{16}$", options: .regularExpression) == nil {
                    print("ECID must be exactly 16 hex characters!")
                    exit(-1)
                }
            }
        }
        
        do {
            var iDevice: PwnUSB<IOKitUSB>!
            try StatusIndicator.new("Connecting to iDevice") { (status) -> String in
                iDevice = try PwnUSB<IOKitUSB>(ecid: ecid)
                
                return "Done!"
            }
            
            if !iDevice.pwned {
                print("Device is not in pwned DFU. Exploiting now.")
                try StatusIndicator.new("Exploiting iDevice") { (status) -> String in
                    try iDevice.exploit(status: status)
                    
                    return "PWNED!"
                }
            }
            
            try sendPatches(patches: iDevice.config.rmsigchksPatches, iDevice: iDevice)
            
            print("-> Pwned DFU mode will now be 'disabled'")
            print("-> Only the signature patches remain")
            print("-> You can now send an iBSS with broken signature")
        } catch let e as USBException {
            if StatusIndicator.globalStatusIndicator != nil {
                StatusIndicator.globalStatusIndicator!.failAndExit(msg: e.message)
            } else {
                StatusIndicator.clear()
                print("An exception occured: \(e.message)")
                exit(-1)
            }
        } catch {
            print("An unknown exception occured!")
            exit(-1)
        }
        
        exit(0)
    }
}
