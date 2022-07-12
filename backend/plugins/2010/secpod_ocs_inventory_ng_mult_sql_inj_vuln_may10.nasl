##############################################################################
# OpenVAS Vulnerability Test
#
# OCS Inventory NG Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902059");
  script_version("2019-05-16T08:02:32+0000");
  script_tag(name:"last_modification", value:"2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_cve_id("CVE-2010-1733");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("OCS Inventory NG Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38311");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/55873");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_ocs_inventory_ng_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ocs_inventory_ng/detected");

  script_tag(name:"insight", value:"The flaws are due to the error in the 'index.php' page, which fails to
  properly verify the user supplied input via the 'search' form for the various
  inventory fields and via the 'All softwares' search form for the 'Software name' field.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to OCS Inventory NG version 1.02.3.");

  script_tag(name:"summary", value:"This host is running OCS Inventory NG and is prone to multiple SQL
  injection vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to to view, add, modify
  or delete information in the back-end database.");

  script_tag(name:"affected", value:"OCS Inventory NG prior to 1.02.3");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

ocsPort = get_http_port(default:80);

ocsVer = get_kb_item("www/"+ ocsPort + "/OCS_Inventory_NG");
if(isnull(ocsVer))
  exit(0);

ocsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ocsVer);
if(ocsVer[1] != NULL)
{
  if(version_is_less(version:ocsVer[1], test_version:"1.02.3")){
    security_message(ocsPort);
  }
}
