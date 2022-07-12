###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_revive_adserver_mult_vuln_oct15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Revive Adserver Multiple Vulnerabilities Oct15
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

CPE = "cpe:/a:revive:adserver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806508");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2015-7364", "CVE-2015-7365", "CVE-2015-7366", "CVE-2015-7367",
                "CVE-2015-7368", "CVE-2015-7369", "CVE-2015-7370", "CVE-2015-7371",
                "CVE-2015-7372", "CVE-2015-7373");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-20 15:41:06 +0530 (Tue, 20 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Revive Adserver Multiple Vulnerabilities Oct15");

  script_tag(name:"summary", value:"The host is installed with Revive Adserver
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Some plugin actions (e.g. enabling, disabling) could be performed via GET
    without any CSRF protection mechanism.

  - 'account-user-*.php' scripts not checking the CSRF token sent via POST
    request.

  - Insufficient restriction on accessing cached copies of pages visited in
    Revive Adserver's admin UI.

  - Default Flash cross-domain policy (crossdomain.xml) does not restrict
    access cross domain access

  - Insufficient sanitization of user-supplied input via 'id' and 'data-file'
    parameters in 'open-flash-chart.swf' script.

  - 'run-mpe.php' script used by the admin UI lacks proper authentication and
    access control.

  - Insufficient sanitization of user-supplied input via 'layerstyle' parameter
    in 'al.php' script.

  - 'magic-macros' feature in Revive Adserver does not sanitize user supplied
    input via different GET parameters.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of of the affected site, to disrupt service, to
  corrupt information, to conduct cross domain attacks, to cause a denial of
  service, include and execute arbitrary local files and to perform some
  unspecified actions and allow local attackers to obtain sensitive
  information.");

  script_tag(name:"affected", value:"Revive Adserver versions before 3.2.2");

  script_tag(name:"solution", value:"Upgrade to Revive Adserver version 3.2.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133893");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Oct/32");
  script_xref(name:"URL", value:"http://www.revive-adserver.com/security/revive-sa-2015-001");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/536633/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_revive_adserver_detect.nasl");
  script_mandatory_keys("ReviveAdserver/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!revPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!revVer = get_app_version(cpe:CPE, port:revPort)){
  exit(0);
}

if(version_is_less( version:revVer, test_version:"3.2.2" ))
{
  report = 'Installed Version: ' + revVer + '\nFixed Version: 3.2.2\n';
  security_message(port:revPort, data:report);
  exit(0);
}
