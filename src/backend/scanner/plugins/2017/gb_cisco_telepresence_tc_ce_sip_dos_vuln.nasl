###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telepresence_tc_ce_sip_dos_vuln.nasl 11962 2018-10-18 10:51:32Z mmartin $
#
# Cisco TelePresence CE and TC Software 'SIP' DoS Vulnerability (cisco-sa-20170607-tele)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811084");
  script_version("$Revision: 11962 $");
  script_cve_id("CVE-2017-6648");
  script_bugtraq_id(98934);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:51:32 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-08 17:37:26 +0530 (Thu, 08 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco TelePresence CE and TC Software 'SIP' DoS Vulnerability (cisco-sa-20170607-tele)");

  script_tag(name:"summary", value:"The host is running Cisco TelePresence
  Endpoint and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a lack of flow-control
  mechanisms within the software.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unauthenticated, remote attacker to cause a TelePresence endpoint to reload
  unexpectedly, resulting in a denial of service (DoS) condition.");

  script_tag(name:"affected", value:"Cisco TC and CE platforms when running
  software versions prior to TC 7.3.8 and CE 8.3.0. This vulnerability affects
  the following Cisco TelePresence products,
  TelePresence MX Series,
  TelePresence SX Series,
  TelePresence Integrator C Series,
  TelePresence System EX Series,
  TelePresence DX Series,
  TelePresence System Profile MXP Series,
  TelePresence Profile Series.");

  script_tag(name:"solution", value:"Upgrade to Cisco TelePresence TC 7.3.8 or
  Cisco TelePresence CE 8.3.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux94002");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-tele");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_telepresence_detect_snmp.nasl", "gb_cisco_telepresence_detect_ftp.nasl");
  script_mandatory_keys("cisco/telepresence/version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!cisport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!version =  get_app_version(cpe:CPE, port:cisport)){
  exit(0);
}

if(!typ = get_kb_item("cisco/telepresence/typ" )) exit( 0 );

## TelePresence MX Series
## http://www.red-thread.com/products/telepresence-mx-series/
## typ !~ 'MX(2|3|7|8)00$' && typ !~ 'G2$' &&  typ !~ ' (42|52)/55$' && typ !~ ' (42|52)/55( Dual$)'
## TelePresence SX Quick Set Series and TelePresence SX Series
## https://blogs.cisco.com/ciscoit/b-c-07232014-cisco-sx-series-adding-tp-to-every-screen
## typ !~ 'SX(1|2|8)0$' && typ !~ 'SpeakerTrack$'
## TelePresence DX Series
## http://cdn2.hubspot.net/hub/160452/file-1411244501-pdf/docs/cisco_dx_series.pdf
## typ !~ 'DX(65|7|8)0$'
## TelePresence System Profile MXP Series
## typ !~ 'MXP'
## TelePresence System EX Series
## typ !~ 'EX(6|9)0$'
## TelePresence Integrator C Series
## typ !~ "C(9|6|4|2)0"
## Not covering TelePresence Profile Series
if(typ !~ 'MX(2|3|7|8)00$' && typ !~ 'G2$' &&  typ !~ ' (42|52)/55$' && typ !~ ' (42|52)/55( Dual$)' &&
   typ !~ 'SX(1|2|8)0$' && typ !~ 'SpeakerTrack$' &&
   typ !~ 'DX(65|7|8)0$' &&
   typ !~ 'MXP' &&
   typ !~ 'EX(6|9)0$' &&
   typ !~ "C(9|6|4|2)0") {
  exit( 0 );
}

## TC and CE affected but pattern coming like(TE)
ciscoVer = eregmatch(pattern:"^T[CE]([^$]+$)", string:version, icase:TRUE);
if(isnull(ciscoVer[1])){
  exit(0);
}

verscat = ciscoVer[0];
vers = ciscoVer[1];

if(verscat =~ "^ce.")
{
  if(vers =~ "^8\.2\.0" || vers =~ "^8\.2\.1" || vers =~ "^8\.2\.2"){
    fix = "8.3.0";
  }
}

else if(verscat =~ "^tc.")
{
  if(vers =~ "^3\.1\.[0|5]" || vers =~ "^4\.2\.[0-4]" || vers =~ "^5\.0\.(0|2)" ||
     vers =~ "^5\.1\.(0|[3-7]|11|13)" || vers =~ "^6\.0\.[1-4]" ||
     vers =~ "^6\.1\.[0-4]" || vers =~ "^4\.1\.[0-2]" || vers =~ "^7\.2\.(0|1)" ||
     vers =~ "^6\.3\.[0-5]" || vers =~ "^7\.3\.([0-3]|[6-7])" || vers =~ "^7\.1\.[0-4]"){
    fix = "7.3.8";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix);
  security_message( port:cisport, data:report);
  exit(0);
}
