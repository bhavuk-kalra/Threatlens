"use client"

import { useEffect } from "react"

export function UIFixes() {
  useEffect(() => {
    // Function to prevent elements from becoming editable
    const preventEditable = () => {
      // Find all buttons and interactive elements
      const interactiveElements = document.querySelectorAll(
        "button, a, [role='button'], .tabs-list, .tabs-trigger, [class*='button'], .badge",
      )

      // Apply non-selectable attributes
      interactiveElements.forEach((el) => {
        el.setAttribute("unselectable", "on")

        // Add CSS classes for non-selectable elements
        el.classList.add("non-selectable")

        // Prevent default behavior on double click
        el.addEventListener("dblclick", (e) => {
          e.preventDefault()
          return false
        })
      })
    }

    // Run on mount
    preventEditable()

    // Set up a mutation observer to handle dynamically added elements
    const observer = new MutationObserver((mutations) => {
      let shouldPreventEditable = false

      // Check if any relevant nodes were added
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          shouldPreventEditable = true
        }
      })

      if (shouldPreventEditable) {
        preventEditable()
      }
    })

    // Start observing the document with a more aggressive configuration
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["class", "style"],
    })

    // Add event listener for results loading
    const handleResultsLoaded = () => {
      // Give time for the DOM to update
      setTimeout(preventEditable, 100)
    }

    // Listen for custom events or state changes
    window.addEventListener("resultsLoaded", handleResultsLoaded)

    // Run preventEditable periodically to catch any missed elements
    const interval = setInterval(preventEditable, 1000)

    // Cleanup
    return () => {
      observer.disconnect()
      window.removeEventListener("resultsLoaded", handleResultsLoaded)
      clearInterval(interval)
    }
  }, [])

  return null
}
