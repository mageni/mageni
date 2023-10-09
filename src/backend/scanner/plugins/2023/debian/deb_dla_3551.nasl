# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3551");
  script_cve_id("CVE-2019-11358", "CVE-2019-12248", "CVE-2019-12497", "CVE-2019-12746", "CVE-2019-13458", "CVE-2019-16375", "CVE-2019-18179", "CVE-2019-18180", "CVE-2020-11022", "CVE-2020-11023", "CVE-2020-1765", "CVE-2020-1766", "CVE-2020-1767", "CVE-2020-1769", "CVE-2020-1770", "CVE-2020-1771", "CVE-2020-1772", "CVE-2020-1773", "CVE-2020-1774", "CVE-2020-1776", "CVE-2021-21252", "CVE-2021-21439", "CVE-2021-21440", "CVE-2021-21441", "CVE-2021-21443", "CVE-2021-36091", "CVE-2021-36100", "CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184", "CVE-2022-4427", "CVE-2023-38060");
  script_tag(name:"creation_date", value:"2023-08-31 04:20:48 +0000 (Thu, 31 Aug 2023)");
  script_version("2023-08-31T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-08-31 05:05:25 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-28 19:27:00 +0000 (Wed, 28 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3551)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3551");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3551");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/otrs2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'otrs2' package(s) announced via the DLA-3551 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in otrs2, the Open-Source Ticket Request System, which could lead to impersonation, denial of service, information disclosure, or execution of arbitrary code.

CVE-2019-11358

A Prototype Pollution vulnerability was discovered in OTRS' embedded jQuery 3.2.1 copy, which could allow sending drafted messages as wrong agent.

This vulnerability is also known as OSA-2020-05.

CVE-2019-12248

Matthias Terlinde discovered that when an attacker sends a malicious email to an OTRS system and a logged in agent user later quotes it, the email could cause the browser to load external image resources.

A new configuration setting Ticket::Frontend::BlockLoadingRemoteContent has been added as part of the fix. It controls whether external content should be loaded, and it is disabled by default.

This vulnerability is also known as OSA-2019-08.

CVE-2019-12497

Jens Meister discovered that in the customer or external frontend, personal information of agents, like Name and mail address in external notes, could be disclosed.

New configuration settings Ticket::Frontend::CustomerTicketZoom###DisplayNoteFrom has been added as part of the fix. It controls if agent information should be displayed in external note sender field, or be substituted with a different generic name. Another option named Ticket::Frontend::CustomerTicketZoom###DefaultAgentName can then be used to define the generic agent name used in the latter case. By default, previous behavior is preserved, in which agent information is divulged in the external note From field, for the sake of backwards compatibility.

This vulnerability is also known as OSA-2019-09.

CVE-2019-12746

A user logged into OTRS as an agent might unknowingly disclose their session ID by sharing the link of an embedded ticket article with third parties. This identifier can be then potentially abused in order to impersonate the agent user.

This vulnerability is also known as OSA-2019-10.

CVE-2019-13458

An attacker who is logged into OTRS as an agent user with appropriate permissions can leverage OTRS tags in templates in order to disclose hashed user passwords.

This vulnerability is also known as OSA-2019-12.

CVE-2019-16375

An attacker who is logged into OTRS as an agent or customer user with appropriate permissions can create a carefully crafted string containing malicious JavaScript code as an article body. This malicious code is executed when an agent compose an answer to the original article.

This vulnerability is also known as OSA-2019-13.

CVE-2019-18179

An attacker who is logged into OTRS as an agent is able to list tickets assigned to other agents, which are in the queue where attacker doesn't have permissions.

This vulnerability is also known as OSA-2019-14.

CVE-2019-18180

OTRS can be put into an endless loop by providing filenames with overly long extensions. This applies to the PostMaster (sending in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'otrs2' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"otrs", ver:"6.0.16-2+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"otrs2", ver:"6.0.16-2+deb10u1", rls:"DEB10"))) {
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
