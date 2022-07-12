###############################################################################
# OpenVAS Vulnerability Test
#
# UseBB BBcode Parsing Remote Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901057");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-4041");
  script_bugtraq_id(37010);
  script_name("UseBB BBcode Parsing Remote Denial Of Service Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37328");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3222");
  script_xref(name:"URL", value:"http://www.usebb.net/community/topic-post9775.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_usebb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("usebb/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code and cause Denial-of-Service by posting a message containing specially crafted BBcode.");

  script_tag(name:"affected", value:"UseBB version 1.0.9 and prior on all platforms.");

  script_tag(name:"insight", value:"This issue is due to an infinite loops while parsing for malformed
  BBcode.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to UseBB version 1.0.10.");

  script_tag(name:"summary", value:"This host has UseBB installed and is prone to Denial of Service
  vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

usebbPort = get_http_port(default:80);

usebbVer = get_kb_item("www/"+ usebbPort + "/UseBB");
if(!usebbVer)
  exit(0);

usebbVer = eregmatch(pattern:"^(.+) under (/.*)$", string:usebbVer);
if(usebbVer[1])
{
  if(version_is_less(version:usebbVer[1], test_version:"1.0.10")){
    security_message(usebbPort);
  }
}
