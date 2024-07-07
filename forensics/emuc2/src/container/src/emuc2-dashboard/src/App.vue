<template>
  <v-app>
    <RouterView />
  </v-app>
</template>

<script setup>

import { RouterView } from 'vue-router';

import { useAuthStore } from '@/stores';

const authStore = useAuthStore();

</script>
