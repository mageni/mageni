###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quick_tftp_44712.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Quick Tftp Server Pro Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100899");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-11-09 13:58:26 +0100 (Tue, 09 Nov 2010)");
  script_bugtraq_id(44712);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Quick Tftp Server Pro Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44712");
  script_xref(name:"URL", value:"http://www.tallsoft.com/tftpserver.htm");

  script_category(ACT_ATTACK);
  script_family("Remote file access");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_windows");
  script_exclude_keys("tftp/backdoor", "keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"Quick Tftp Server Pro is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to retrieve arbitrary
  files outside of the FTP server root directory. This may aid in further attacks.");

  script_tag(name:"affected", value:"Quick Tftp Server Pro 2.1 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if(!port)
  port = 69;

if(!get_udp_port_state(port))
  exit(0);

if(get_kb_item("tftp/" + port + "/backdoor"))
  exit(0);

files = traversal_files("windows");

foreach file(keys(files)) {

  res = tftp_get(port:port, path:"../../../../../../../../../../../../" + files[file]);
  if(!res)
    continue;

  if(egrep(pattern:file, string:res, icase:TRUE)) {
    report = string("The " + files[file] + " file contains:\n", res);
    security_message(port:port, data:report, proto:"udp");
    exit(0);
  }
}

exit(99);