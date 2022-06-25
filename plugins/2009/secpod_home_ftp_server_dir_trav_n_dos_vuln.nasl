###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_home_ftp_server_dir_trav_n_dos_vuln.nasl 13610 2019-02-12 15:17:00Z cfischer $
#
# Home FTP Server DOS And Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.SecPod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900260");
  script_version("$Revision: 13610 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 16:17:00 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4051", "CVE-2009-4053");
  script_bugtraq_id(37033);
  script_name("Home FTp Server DOS And Multiple Directory Traversal Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37381");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2009/Nov/111");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3269");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("secpod_home_ftp_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("HomeFTPServer/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to to cause a Denial of Service
  or directory traversal attacks on the affected application.");

  script_tag(name:"affected", value:"Home FTP Server version 1.10.1.139 and prior.");

  script_tag(name:"insight", value:"- An error in the handling of multiple 'SITE INDEX' commands can be exploited
  to stop the server.

  - An input validation error when handling the MKD FTP command can be exploited
  to create directories outside the FTP root or create files with any contents
  in arbitrary directories via directory traversal sequences in a file upload request.");

  script_tag(name:"solution", value:"Upgrade to Home FTP Server version 1.10.3.144 or later.");

  script_tag(name:"summary", value:"The host is running Home Ftp Server and is prone to Denial of Service and
  Directory Traversal Vulnerabilities using invalid commands.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://downstairs.dnsalias.net/homeftpserver.html");

  exit(0);
}

include("version_func.inc");
include("ftp_func.inc");

hftpPort = get_ftp_port(default:21);
if("Home Ftp Server" >!< get_ftp_banner(port:hftpPort)){
  exit(0);
}

if(!safe_checks())
{
  soc1 = open_sock_tcp(hftpPort);
  if(soc1)
  {

    kb_creds = ftp_get_kb_creds();
    user = kb_creds["login"];
    pass = kb_creds["pass"];

    ftplogin = ftp_log_in(socket:soc1, user:user, pass:pass);
    test_string= crap(length:30, data:"a");

    if(ftplogin)
    {
      for( j = 1; j <= 11; j++ )
      {
        send(socket:soc1, data:string("SITE INDEX ", test_string * j ,"\r\n"));
        soc2 = open_sock_tcp(hftpPort);
        resp = ftp_recv_line(socket:soc2);
        if(!resp)
        {
          security_message(hftpPort);
          close(soc2);
          exit(0);
        }
        close(soc2);
      }
    }
    close(soc1);
  }
}

hftpVer = get_kb_item("HomeFTPServer/Ver");
if(!hftpVer){
  exit(0);
}

if(version_is_less_equal(version:hftpVer, test_version:"1.10.1.139")){
  security_message(hftpPort);
}
