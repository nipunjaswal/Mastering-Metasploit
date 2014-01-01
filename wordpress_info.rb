require 'rex/proto/http'
require 'msf/core'
class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	def initialize
		super(
			'Name'        => 'Wordpress Version Detector',
			'Description' => 'Detects Running Version Of Wordpress',
			'Author'      => 'Nipun_Jaswal',
			'License'     => MSF_LICENSE
		)
	end
	def run_host(ip)
		begin
			connect
			res = send_request_raw({'uri' => '/~serverc/HOWTOTALKDIRTY.ORG/readme.html', 'method' => 'GET' })
			g= (res.body =~ /[V]ersion/)
			n=g.to_i+8
			ver= res.body[n,5]
			print_line("Bitch is Running Wordpress #{ver}")
		end
	end

end
