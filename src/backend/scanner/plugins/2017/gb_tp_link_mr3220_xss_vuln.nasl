###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tp_link_mr3220_xss_vuln.nasl 12108 2018-10-26 06:41:17Z asteins $
#
# TP-Link TL-MR3220 Cross-Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/h:tp-link:wireless-n_router";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811881");
  script_version("$Revision: 12108 $");
  script_cve_id("CVE-2017-15291");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:41:17 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-25 15:11:30 +0530 (Wed, 25 Oct 2017)");
  script_name("TP-Link TL-MR3220 Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running TP-Link TL-MR3220
  Wireless N Router and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed model with the help
  of detect NVT and check the model is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user supplied input via Description field in Wireless MAC
  Filtering page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  users to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"TP-LINK TL-MR3220");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");


  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://fireshellsecurity.team/assets/pdf/Router-TP-LINK-TL-MR3220-Vulnerability-XSS.pdf");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43023");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_tp_link_wireless_n_router_detect.nasl");
  script_mandatory_keys("TP-LINK/Wireless/Router/model");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tlPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!model = get_kb_item("TP-LINK/Wireless/Router/model")){
  exit(0);
}

if(model == "MR3220"){
  report = report_fixed_ver(installed_version:"TP-LINK Wireless Router " + model, fixed_version:"WillNotFix");
  security_message(data:report, port:tlPort);
  exit(0);
}

exit(99);
