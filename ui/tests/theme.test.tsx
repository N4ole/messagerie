import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeToggle } from "../src/components/ThemeToggle";

describe("Thème clair/sombre", () => {
  it("cycle système → clair → sombre → système et mémorise le choix", async () => {
    render(<ThemeToggle />);
    const btn = screen.getByRole("button");
    expect(document.documentElement.getAttribute("data-theme")).toBeNull();
    await userEvent.click(btn);
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
    await userEvent.click(btn);
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(window.localStorage.getItem("messagerie.theme")).toBe("dark");
    await userEvent.click(btn);
    expect(document.documentElement.getAttribute("data-theme")).toBeNull();
  });
});
