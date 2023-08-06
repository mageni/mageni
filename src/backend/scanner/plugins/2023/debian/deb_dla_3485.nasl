# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3485");
  script_cve_id("CVE-2022-39369");
  script_tag(name:"creation_date", value:"2023-07-10 04:22:05 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-05 01:52:00 +0000 (Sat, 05 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-3485)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3485");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3485");
  script_xref(name:"URL", value:"https://github.com/apereo/phpCAS/blob/f3db27efd1f5020e71f2116f637a25cc9dbda1e3/docs/Upgrading#L1C1-L1C1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php-cas");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-cas' package(s) announced via the DLA-3485 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been found in phpCAS, a Central Authentication Service client library in php, which may allow an attacker to gain access to a victim's account on a vulnerable CASified service without victim's knowledge, when the victim visits attacker's website while being logged in to the same CAS server.

The fix for this vulnerabilty requires an API breaking change in php-cas and will require that software using the library be updated.

For buster, all packages in the Debian repositories which are using php-cas have been updated, though additional manual configuration is to be expected, as php-cas needs additional site information -- the service base URL -- for it to function. The DLAs for the respective packages will have additional information, as well as the package's NEWS files.

For 3rd party software using php-cas, please be note that upstream provided following instructions how to update this software [1]:

phpCAS now requires an additional service base URL argument when constructing the client class. It accepts any argument of:

1. A service base URL string. The service URL discovery will always use this server name (protocol, hostname and port number) without using any external host names. 2. An array of service base URL strings. The service URL discovery will check against this list before using the auto discovered base URL. If there is no match, the first base URL in the array will be used as the default. This option is helpful if your PHP website is accessible through multiple domains without a canonical name, or through both HTTP and HTTPS. 3. A class that implements CAS_ServiceBaseUrl_Interface. If you need to customize the base URL discovery behavior, you can pass in a class that implements the interface.

Constructing the client class is usually done with phpCAS::client().

For example, using the first possiblity: phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context), could become: phpCAS::client(CAS_VERSION_2_0, $cas_host, $cas_port, $cas_context, 'https://casified-service.example.org:8080'),

Details of the vulnerability:

CVE-2022-39369

The phpCAS library uses HTTP headers to determine the service URL used to validate tickets. This allows an attacker to control the host header and use a valid ticket granted for any authorized service in the same SSO realm (CAS server) to authenticate to the service protected by phpCAS. Depending on the settings of the CAS server service registry in worst case this may be any other service URL (if the allowed URLs are configured to '^(https)://.*') or may be strictly limited to known and authorized services in the same SSO federation if proper URL service validation is applied.

[1] [link moved to references]

For Debian 10 buster, this problem has been fixed in version 1.3.6-1+deb10u1.

We recommend that you upgrade your php-cas packages.

For the detailed security status of php-cas please refer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php-cas' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"php-cas", ver:"1.3.6-1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
