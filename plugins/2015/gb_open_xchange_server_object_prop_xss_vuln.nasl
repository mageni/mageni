###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_xchange_server_object_prop_xss_vuln.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Open-Xchange (OX) Server Object Properties Cross Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:open-xchange:open-xchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806526");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-5375");
  script_bugtraq_id(76837);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-02 12:36:19 +0530 (Mon, 02 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Open-Xchange (OX) Server Object Properties Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is installed with
  Open-Xchange (OX) Server and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to insufficient
  sanitization of user supplied input via unknown vectors related to object
  properties.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML in the browser of an
  unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"Open-Xchange (OX) Server version 6 and
  prior.");

  script_tag(name:"solution", value:"Upgrade to Open-Xchange (OX) Server version
  6.22.9-rev15m or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536523/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ox_server_detect.nasl");
  script_mandatory_keys("open_xchange_server/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.open-xchange.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!oxsPort = get_app_port(cpe:CPE)){
  exit(0);
}

oxsVer = get_app_version(cpe:CPE, port:oxsPort);
if(!oxsVer || "unknown" >< oxsVer){
  exit(0);
}

oxRev = get_kb_item("open_xchange_server/" + oxsPort + "/rev");

if(oxRev)
{
  ## Updating version with revision number
  oxsVer = oxsVer + "." + oxRev;

  if(oxsVer =~ "^6")
  {
    if(version_is_equal(version:oxsVer, test_version:"6.22.9"))
    {
      report = 'Installed Version: ' + oxsVer + '\nFixed Version:     6.22.9-rev15m\n';
      security_message(data:report,port:oxsPort);
      exit(0);
    }
  }
}

exit(99);