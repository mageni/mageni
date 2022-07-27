# OpenVAS Vulnerability Test
# $Id: tftp_files_hp_ignite_ux.nasl 13194 2019-01-21 13:18:47Z cfischer $
# Description: TFTP file detection (HP Ignite-UX)
#
# Authors:
# Martin O'Neal of Corsaire (http://www.corsaire.com)
#
# Copyright:
# Copyright (C) 2005 Corsaire Limited
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19508");
  script_version("$Revision: 13194 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 14:18:47 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("TFTP file detection (HP Ignite-UX)");
  script_category(ACT_ATTACK);
  script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "tftpd_backdoor.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_unixoide");
  script_exclude_keys("keys/TARGET_IS_IPV6", "tftp/backdoor");

  script_tag(name:"solution", value:"If it is not required, disable or uninstall the TFTP server.
  Otherwise restrict access to trusted sources only.");

  script_tag(name:"summary", value:"The remote host has a TFTP server installed that is serving one or more
  sensitive HP Ignite-UX files.");

  script_tag(name:"impact", value:"These files potentially include sensitive information about the hardware and
  software configuration of the HPUX host, so should not be exposed to unnecessary scrutiny.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if(!port)
  port = 69;

if(!get_udp_port_state(port))
  exit(0);

if(get_kb_item("tftp/" + port + "/backdoor"))
  exit(0);

if(get_kb_item("tftp/" + port + "/rand_file_response"))
  exit(0);

file_list = make_list(
"/var/opt/ignite/config.local", "/var/opt/ignite/local/config", "/var/opt/ignite/local/host.info",
"/var/opt/ignite/local/hw.info", "/var/opt/ignite/local/install.log", "/var/opt/ignite/local/manifest/manifest",
"/var/opt/ignite/recovery/makrec.append", "/var/opt/ignite/server/ignite.defs", "/var/opt/ignite/server/preferences");

foreach file_name(file_list) {
  if(tftp_get(port:port, path:file_name)) {
    detected_files += file_name + '\n';
  }
}

if(detected_files) {
  report = 'The filenames detected are:\n\n' + detected_files;
  security_message(port:port, data:report, proto:"udp");
  exit(0);
}

exit(99);