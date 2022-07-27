###############################################################################
# OpenVAS Vulnerability Test
#
# Xymon Monitor Unspecified Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902504");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-1716");
  script_bugtraq_id(47156);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Xymon Monitor Unspecified Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44036");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66542");
  script_xref(name:"URL", value:"http://xymon.svn.sourceforge.net/viewvc/xymon/branches/4.3.2/Changes?revision=6673&view=markup");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_xymon_monitor_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xymon/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Xymon Monitor versions 4.3.0 and prior.");

  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input by
  multiple unspecified scripts which allows attackers to execute arbitrary
  HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Xymon Monitor version 4.3.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is running Xymon Monitor and is prone to unspecified
  multiple cross site scripting vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(vers = get_version_from_kb(port:port,app:"Xymon"))
{
  if(version_is_less_equal(version:vers, test_version:"4.3.0")){
    security_message(port:port);
  }
}
