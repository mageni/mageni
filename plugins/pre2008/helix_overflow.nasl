# OpenVAS Vulnerability Test
# $Id: helix_overflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Helix RealServer Buffer Overrun
#
# Authors:
# Keith Young
#
# Copyright:
# Copyright (C) 2003 Montgomery County Maryland Government Security Team
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
  script_oid("1.3.6.1.4.1.25623.1.0.11642");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8476);
  script_cve_id("CVE-2003-0725");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Helix RealServer Buffer Overrun");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Montgomery County Maryland Government Security Team");
  script_family("Gain a shell remotely");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 554);
  script_mandatory_keys("RTSP/banner/available");

  script_tag(name:"solution", value:"Install patches from the vendor.");

  script_tag(name:"summary", value:"RealServer 8.0 and earlier and Helix Server 9.0 is
  vulnerable to a buffer overflow.");

  script_xref(name:"URL", value:"http://service.real.com/help/faq/security/bufferoverrun030303.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

port = get_kb_item("Services/rtsp");
if(!port)
  port = 554;

serverbanner = get_kb_item("RTSP/" + port + "/Server");
if(!serverbanner || "Version " >!< serverbanner)
  exit(0);

# Currently, all versions up to and including 9.0.1 are affected
if((egrep(pattern:"Version [0-8]\.[0-9]", string:serverbanner)) || (egrep(pattern:"Version 9\.0\.[0-1]", string:serverbanner)) ) {
  security_message(port:port);
  exit(0);
}

exit(99);