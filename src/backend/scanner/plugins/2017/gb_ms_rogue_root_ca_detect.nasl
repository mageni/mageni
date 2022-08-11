###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_rogue_root_ca_detect.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Microsoft Windows Rogue Root Certificate Authorities Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112140");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-24 13:11:25 +0100 (Fri, 24 Nov 2017)");

  script_cve_id("CVE-2015-2077", "CVE-2015-2078");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Microsoft Windows Rogue Root Certificate Authorities Detection");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"Mitigation");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"One or more dangerous self-signed certificates are present on the host machine.");
  script_tag(name:"vuldetect", value:"The script checks the target for the existence of self-signed root certificates that could possibly intercept HTTP(S) traffic.");
  script_tag(name:"impact", value:"Successful exploitation might allow attackers to use Man in the Middle attacks against the target and its users to show them manipulated HTTPS webpages or read their encrypted data.");
  script_tag(name:"solution", value:"Ensure that the affected certificates are not being trusted anymore.");

  script_xref(name:"URL", value:"https://blog.hboeck.de/archives/876-Superfish-2.0-Dangerous-Certificate-on-Dell-Laptops-breaks-encrypted-HTTPS-Connections.html");
  script_xref(name:"URL", value:"https://support.lenovo.com/de/en/product_security/superfish");
  script_xref(name:"URL", value:"https://blog.dell.com/en-us/response-to-concerns-regarding-edellroot-certificate/");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securityadvisories/2015/3119884");


  exit(0);
}

include("smb_nt.inc");

## Certificates Path
prefix = "SOFTWARE\Microsoft\SystemCertificates\";
keys = make_list(
  ## Third-Party Root
  prefix + "AuthRoot\Certificates\",
  ## Intermediate (usually untrusted but checking just in case)
  prefix + "CA\Certificates\"
);

## The invalid certificates and their thumbprints
certs = make_list(
  ## Adguard CA R73
  "E4CDCDEECA764FC4196B4E6CF8BAAF7659140620",
  "3A8E038CFB17523CE3323D857DC18FC9E8A5CF0D",
  ## DSDTestProvider
  "02C2D931062D7B1DC2A5C7F5F0685064081FB221",
  ## eDellRoot
  "98A04E4163357790C4A79E6D713FF0AF51FE6927",
  ## Harmony
  "2B52EB9E5F91360170543786190B66D1E47B6709",
  "0874A3219367D67070C0F6D15D8FB55E03AE581B",
  ## KeepMyFamilySecure
  "D468C4971AD856CC96F8B9B4B2D6A1B8040E26BD",
  ## Kurupira.NET
  "B49438B65F42E2CB43666BC23CFFE531CE7F6D46",
  "BE90F13A20F8DE5537BF62CFCD5B3CDEFD43B9EA",
  ## PrivDog Secure Connection Inspector CA
  "7182D5BF77E74168D93C56C841791D1EF2D74506",
  "46C50A91E5AC1E4D6D090CCA2DCD74B7FFF39040",
  ## Qustodio CA
  "653B739F5898BB9C031B1DBCED66E131FDC6BCB8",
  "27980262382C7BA633E1E6879428D67B13FE7429",
  ## Superfish, Inc.
  "C864484869D41D2B0D32319C5A62F9315AAF2CBD"
);

report = 'The following self-signed certificates have been identified and should be untrusted and/or removed from the host machine:\n';

foreach key (keys) {
  foreach cert (certs) {
    if (registry_key_exists(key:key+cert)) {
      VULN = TRUE;
      report += '\n' + key + cert;
    }
  }
}

if(VULN) {
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
