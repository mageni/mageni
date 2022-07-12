###############################################################################
# OpenVAS Vulnerability Test
#
# osCSS 'page' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901134");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2010-2856");
  script_bugtraq_id(41510);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("osCSS 'page' Parameter Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40502");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60203");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1770");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/xss_vulnerability_in_oscss.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_oscss_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oscss/detected");

  script_tag(name:"impact", value:"Successful exploitation could result in a compromise of the
  application, theft of cookie-based authentication credentials, disclosure or
  modification of sensitive data.");

  script_tag(name:"affected", value:"osCSS Version 1.2.2 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
  via the 'page' parameter in 'admin/currencies.php' that allows the attackers to
  execute arbitrary HTML and script code in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running osCSS and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

ver = get_kb_item("www/" + port + "/osCSS");
ocVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(ocVer[1])
{
  if(version_is_less(version:ocVer[1], test_version:"1.2.2")){
    security_message(port);
  }
}
