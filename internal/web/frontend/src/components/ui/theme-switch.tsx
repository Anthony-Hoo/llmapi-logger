import { THEME_OPTIONS, useThemePreference } from "../../lib/theme";
import { Segmented } from "./segmented";

/**
 * Three-way theme switch: follow the system, or pin the light or the dark
 * theme. It sits in the page header and on the sign-in page.
 */
export function ThemeSwitch() {
  const [preference, setPreference] = useThemePreference();
  return <Segmented label="主题" value={preference} options={THEME_OPTIONS} onChange={setPreference} />;
}
