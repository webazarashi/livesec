import { describe, expect, it } from "vitest";
import { formatPurl, osvToPurl, parsePurl, purlToOsv, purlWithoutVersion } from "../src/purl";
import { isLinePackage, topicForPackage } from "../src/topics";

describe("PURL", () => {
  it("スコープ付きnpmを読む", () => {
    const p = parsePurl("pkg:npm/%40line/liff@2.24.0");
    expect(p).toMatchObject({ type: "npm", namespace: "@line", name: "liff", version: "2.24.0" });
    expect(purlToOsv(p!)).toEqual({ ecosystem: "npm", name: "@line/liff", version: "2.24.0" });
    expect(formatPurl({ type: "npm", namespace: "@line", name: "liff", version: null })).toBe("pkg:npm/%40line/liff");
  });
  it("LINE SDK を各言語で判定する（3-4）", () => {
    expect(purlToOsv("pkg:pypi/line-bot-sdk@3.1.0")).toEqual({ ecosystem: "PyPI", name: "line-bot-sdk", version: "3.1.0" });
    expect(purlToOsv("pkg:gem/line-bot-api@1.29.0")?.ecosystem).toBe("RubyGems");
    expect(purlToOsv("pkg:composer/linecorp/line-bot-sdk@9.0.0")).toEqual({
      ecosystem: "Packagist",
      name: "linecorp/line-bot-sdk",
      version: "9.0.0",
    });
    const go = purlToOsv("pkg:golang/github.com/line/line-bot-sdk-go/v8@v8.3.0");
    expect(go).toEqual({ ecosystem: "Go", name: "github.com/line/line-bot-sdk-go/v8", version: "8.3.0" });
    expect(isLinePackage("Go", go!.name)).toBe(true);
    expect(topicForPackage("npm", "@line/bot-sdk")).toBe("line");
    expect(topicForPackage("npm", "express")).toBe("npm");
  });
  it("OSパッケージ（Debian・Alpine）", () => {
    expect(purlToOsv("pkg:deb/debian/libssl3@3.0.15-1~deb12u1?arch=amd64&distro=debian-12&upstream=openssl")).toEqual({
      ecosystem: "Debian:12",
      name: "openssl",
      version: "3.0.15-1~deb12u1",
    });
    expect(purlToOsv("pkg:apk/alpine/busybox@1.36.1-r29?arch=x86_64&distro=alpine-3.20.3")).toEqual({
      ecosystem: "Alpine:v3.20",
      name: "busybox",
      version: "1.36.1-r29",
    });
    expect(osvToPurl("Debian:12", "openssl")).toBe("pkg:deb/debian/openssl?distro=debian-12");
    expect(topicForPackage("Debian:12", "linux")).toBeNull();
  });
  it("バージョンなしにする", () => {
    expect(purlWithoutVersion("pkg:npm/express@4.17.1")).toBe("pkg:npm/express");
  });
  it("PURLでないものは null", () => {
    expect(parsePurl("express@4")).toBeNull();
  });
});
