# OpenVAS Vulnerability Test
# $Id: tftp_files_cisco_ios_ca.nasl 13194 2019-01-21 13:18:47Z cfischer $
# Description: TFTP file detection (Cisco IOS CA)
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

# The script will test whether the remote host has one of a number of sensitive
# files present on the tftp server
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with
# no warranties or guarantees of fitness of use or otherwise. Corsaire
# accepts no responsibility for any damage caused by the use or misuse of
# this information.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17341");
  script_version("$Revision: 13194 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 14:18:47 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("TFTP file detection (Cisco IOS CA)");
  script_category(ACT_ATTACK);
  script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_unixoide");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"summary", value:"The remote host has a TFTP server installed that is serving one or more
  sensitive Cisco IOS Certificate Authority (CA) files.");

  script_tag(name:"insight", value:"These files potentially include the private key for the CA so should be considered
  extremely sensitive and should not be exposed to unnecessary scrutiny.");

  script_tag(name:"solution", value:"If it is not required, disable the TFTP server. Otherwise restrict access to
  trusted sources only.");

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

if(get_kb_item("tftp/" + port + "/rand_file_response"))
  exit(0);

postfix_list = make_list(".pub", ".crl", ".prv", ".ser", "#6101CA.cer", ".p12");

for( i = 1; i < 10; i++) {

  file_name = raw_string(ord(i), '.cnm');

  if(request_data = tftp_get(port:port, path:file_name)) {

    ca_name = eregmatch(string:request_data, pattern:'subjectname_str = cn=(.+),ou=');
    if(ca_name[1]) {
      detected_files = raw_string(detected_files, file_name, "\n");
      foreach file_postfix(postfix_list) {
        file_name = raw_string(ca_name[1], file_postfix);
        if(tftp_get(port:port, path:file_name)) {
          detected_files += file_name + '\n';
        }
      }
      break;
    }
  }
}

if(detected_files) {
  report = 'The filenames detected are:\n\n' + detected_files;
  security_message(port:port, data:report, proto:"udp");
  exit(0);
}

exit(99);