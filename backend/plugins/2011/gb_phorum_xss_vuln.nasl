###############################################################################
# OpenVAS Vulnerability Test
#
# Phorum 'real_name' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802161");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-3392");
  script_bugtraq_id(49347);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Phorum 'real_name' Parameter Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45787");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69456");
  script_xref(name:"URL", value:"http://holisticinfosec.org/content/view/184/45/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phorum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phorum/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Phorum version prior to 5.2.17.");

  script_tag(name:"insight", value:"The flaw is due to input passed via the 'real_name' parameter to the
  'control.php' script is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade Phorum to 5.2.17 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is running Phorum and is prone to cross-site scripting
  vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

phorumPort = get_http_port(default:80);

phorumVer =  get_version_from_kb(port:phorumPort, app:"phorum");
if(!phorumVer)
  exit(0);

if(version_is_less(version:phorumVer, test_version:"5.2.17")){
  security_message(phorumPort);
}
