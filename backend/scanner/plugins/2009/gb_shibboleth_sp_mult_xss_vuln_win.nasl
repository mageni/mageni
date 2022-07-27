###############################################################################
# OpenVAS Vulnerability Test
#
# Shibboleth Service Provider Multiple XSS Vulnerabilities (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801148");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-11-13 15:48:12 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3300");
  script_name("Shibboleth Service Provider Multiple XSS Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37237/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54140");
  script_xref(name:"URL", value:"http://shibboleth.internet2.edu/secadv/secadv_20091104.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_shibboleth_sp_detect_win.nasl");
  script_mandatory_keys("Shibboleth/SP/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to inject arbitrary web
  script or HTML via URLs that are encountered in redirections, and appear in
  automatically generated forms.");
  script_tag(name:"affected", value:"Shibboleth Service Provider version 1.3.x before 1.3.5 and 2.x before 2.3
  on Windows.");
  script_tag(name:"insight", value:"The flaws are due to an error within the sanitation of certain URLs.
  This can be exploited to insert arbitrary HTML and script code, which will
  be executed in a user's browser session in the context of an affected site
  when malicious data is viewed.");
  script_tag(name:"solution", value:"Upgrade Shibboleth Service Provider version 1.3.5 or 2.3 or later.");
  script_tag(name:"summary", value:"The host has Shibboleth Service Provider installed and is prone to
  multiple Cross-Site Scripting vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

shibVer = get_kb_item("Shibboleth/SP/Win/Ver");
if(!shibVer)
  exit(0);

if(version_in_range(version:shibVer, test_version:"1.3", test_version2:"1.3.4")||
   version_in_range(version:shibVer, test_version:"2.0", test_version2:"2.2")){
  security_message(port:0);
}
