###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_98295_lin.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# WordPress Password Reset CVE-2017-8295 Security Bypass Vulnerability (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108155");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-8295");
  script_bugtraq_id(98295);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-08 11:00:15 +0200 (Mon, 08 May 2017)");
  script_name("WordPress Password Reset CVE-2017-8295 Security Bypass Vulnerability (Linux)");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41963/");
  script_xref(name:"URL", value:"https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98295");
  script_xref(name:"URL", value:"https://httpd.apache.org/docs/2.4/mod/core.html#usecanonicalname");

  script_tag(name:"summary", value:"This host is running WordPress and is prone to a security-bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist because WordPress relies on the Host HTTP header for a password-reset e-mail message,
  which makes it easier for user-assisted remote attackers to reset arbitrary passwords by making a crafted wp-login.php?action=lostpassword
  request and then arranging for this e-mail to bounce or be resent, leading to transmission of the reset key to a mailbox on an
  attacker-controlled SMTP server. This is related to problematic use of the SERVER_NAME variable in wp-includes/pluggable.php in
  conjunction with the PHP mail function.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security restrictions to perform unauthorized actions.
  This may aid in further attacks.");

  script_tag(name:"affected", value:"WordPress versions 4.7.4 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.

  A workaround is to enable UseCanonicalName to enforce static SERVER_NAME value.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"4.7.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
